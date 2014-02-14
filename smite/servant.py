import time
import threading
import traceback
import logging
import inspect
from types import ModuleType

import zmq
import msgpack
from zope.dottedname.resolve import resolve

from smite.aes_cipher import AESCipher
from smite.exceptions import (
    ServantBindError,
    MessageRecvError,
    RoutineStop,
)


DEFAULT_THREADS_NUM = 5

_STATS_TMPL = {
    'received_messages': 0,
    'processed_messages': 0,
    'malicious_messages': 0,
    'exceptions': 0,
}


log = logging.getLogger('smite.servant')


class Servant(object):

    def __init__(self, methods=None, threads_num=DEFAULT_THREADS_NUM):
        self.methods = {}

        if isinstance(methods, (list, tuple)):
            map(self.register_method, methods)

        elif isinstance(methods, dict):
            for name, method in methods.iteritems():
                self.register_method(method, name)

        elif methods is not None:
            raise ValueError('Invalid \'methods\' argument type: {}'
                             .format(type(methods)))

        self.threads_num = threads_num
        self.backend_uri = 'inproc://smite-backend'
        self.stats = {'threads': {}, 'summary': _STATS_TMPL.copy()}
        self._lock = threading.Lock()

    def set_opts(self, threads_num=None):
        self.threads_num = threads_num | self.threads_num

    def register_method(self, method, name=None):
        if not callable(method):
            raise ValueError('{} is not callable'.format(method))

        if name is None:
            if inspect.isfunction(method):
                name = method.__name__
            elif hasattr(method, '__class__'):
                name = method.__class__.__name__

        if name in self.methods:
            raise ValueError('Method named \'{}\' is already registered'
                             .format(name))

        self.methods[name] = method

    def expose_module(self, module):
        if not isinstance(module, (str, ModuleType)):
            raise ValueError('Invalid \'module\' argument type: {}'
                             .format(type(module)))

        if isinstance(module, str):
            module = resolve(module)

        module_functions = filter(
            lambda fn: (fn[1].__module__ == module.__name__
                        and not fn[0].startswith('_')),
            inspect.getmembers(module, inspect.isfunction)
        )
        for fname, fn in module_functions:
            self.register_method(fn, '{}.{}'.format(module.__name__, fname))

    def bind(self, host, port):
        self.ctx = zmq.Context()
        self.frontend = self.ctx.socket(zmq.ROUTER)

        try:
            uri = 'tcp://{}:{}'.format(host, port)
            self.frontend.bind(uri)
            log.info('Servant listening at {}'.format(uri))
        except zmq.error.ZMQError as e:
            exc = ServantBindError(
                'Cannot bind to {}:{} ({})'
                .format(host, port, e.strerror)
            )
            log.exception(exc)
            raise exc

        self.backend = self.ctx.socket(zmq.DEALER)
        self.backend.bind(self.backend_uri)

    def run(self):
        self._run = True
        threads = []
        for i in xrange(self.threads_num):
            thread = threading.Thread(target=self.routine)
            thread.daemon = True
            thread.start()
            self.stats['threads'][thread.name] = _STATS_TMPL.copy()
            threads.append(thread)

        poll = zmq.Poller()
        poll.register(self.frontend, zmq.POLLIN)
        poll.register(self.backend,  zmq.POLLIN)

        while self._run:
            sockets = dict(poll.poll(1000))

            if self.frontend in sockets:
                if sockets[self.frontend] == zmq.POLLIN:
                    id_ = self.frontend.recv()
                    msg = self.frontend.recv()
                    self.backend.send(id_, zmq.SNDMORE)
                    self.backend.send(msg)

            if self.backend in sockets:
                if sockets[self.backend] == zmq.POLLIN:
                    id_ = self.backend.recv()
                    msg = self.backend.recv()
                    self.frontend.send(id_, zmq.SNDMORE)
                    self.frontend.send(msg)

        for thread in threads:
            self.backend.send('__break__')

        for thread in threads:
            thread.join()

        self.frontend.close()
        self.backend.close()
        self.ctx.term()

    def stop(self):
        self._run = False

    def routine(self):
        socket = self.ctx.socket(zmq.DEALER)
        socket.connect(self.backend_uri)

        # wait for variables to be set
        # TODO: it's stupid, change it
        time.sleep(.2)
        thread_stats = self.stats['threads'][threading.current_thread().name]
        summary_stats = self.stats['summary']

        def increment_stat(name):
            with self._lock:
                thread_stats[name] += 1
                summary_stats[name] += 1

        while True:
            try:
                id_, msg = self._recv(socket)
            except MessageRecvError:
                increment_stat('received_messages')
                increment_stat('malicious_messages')
                continue
            except RoutineStop:
                break

            increment_stat('received_messages')

            try:
                msg = msgpack.unpackb(msg)
                log.info('Received message: {}'.format(msg))
            except:
                log.warn('Message unpack failed')
                increment_stat('malicious_messages')
                # do not bother to reply if client sent some trash
                continue

            try:
                method = self.methods[msg['_method']]
                rep = {'_result': method(*msg['args'], **msg['kwargs'])}
            except Exception, e:
                increment_stat('exceptions')
                rep = {
                    '_error': 50,
                    '_exc_msg': e.message if hasattr(e, 'message') else '',
                    '_traceback': traceback.format_exc(),
                }

            rep['_uid'] = msg['_uid']

            log.info('Sending reply: {}'.format(rep))
            id_, rep = self._prepare_reply(id_, rep)
            socket.send(id_, zmq.SNDMORE)
            socket.send(rep)
            increment_stat('processed_messages')

        socket.close()

    def _recv(self, socket):
        id_ = socket.recv()
        if id_ == '__break__':
            raise RoutineStop()
        msg = socket.recv()
        return id_, msg

    def _prepare_reply(self, id_, rep):
        return id_, msgpack.packb(rep)


class SecureServant(Servant):

    def __init__(self, methods, secret_key, threads_num=DEFAULT_THREADS_NUM):
        super(SecureServant, self).__init__(methods, threads_num)
        self.cipher = AESCipher(secret_key)

    def _recv(self, socket):
        id_, msg = super(SecureServant, self)._recv(socket)
        dec_msg = self.cipher.decrypt(msg)
        return id_, dec_msg

    def _prepare_reply(self, id_, rep):
        id_, rep = super(SecureServant, self)._prepare_reply(id_, rep)
        return id_, self.cipher.encrypt(rep)
