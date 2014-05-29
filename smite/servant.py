import time
import threading
import traceback
import logging
import inspect
import uuid
import sys
from types import ModuleType
from threading import Lock

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
        self.backend_uri = ('inproc://smite-backend-{}'
                            .format(uuid.uuid1().hex))
        self.stats = {'threads': {}, 'summary': _STATS_TMPL.copy()}
        self._lock = threading.Lock()
        self._default_method = None

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

    def set_default_method(self, method):
        self._default_method = method

    def expose_module(self, module):
        if not isinstance(module, (str, unicode, ModuleType)):
            raise ValueError('Invalid \'module\' argument type: {}'
                             .format(type(module)))

        if isinstance(module, (str, unicode)):
            module = resolve(module)

        module_functions = filter(
            lambda fn: (fn[1].__module__ == module.__name__
                        and not fn[0].startswith('_')),
            inspect.getmembers(module, inspect.isfunction)
        )
        for fname, fn in module_functions:
            self.register_method(fn, '{}.{}'.format(module.__name__, fname))

    def bind(self, bind_uri):
        self.bind_uri = bind_uri
        self._bind()

    def bind_tcp(self, host, port):
        self.bind_uri = 'tcp://{}:{}'.format(host, port)
        self._bind()

    def bind_ipc(self, address):
        self.bind_uri = 'ipc://{}'.format(address)
        self._bind()

    def bind_inproc(self, address):
        self.bind_uri = 'inproc://{}'.format(address)
        self._bind()

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
                    while True:
                        recv = self.frontend.recv()
                        if self.frontend.getsockopt(zmq.RCVMORE):
                            self.backend.send(recv, zmq.SNDMORE)
                        else:
                            self.backend.send(recv)
                            break

            if self.backend in sockets:
                if sockets[self.backend] == zmq.POLLIN:
                    while True:
                        recv = self.backend.recv()
                        if self.backend.getsockopt(zmq.RCVMORE):
                            self.frontend.send(recv, zmq.SNDMORE)
                        else:
                            self.frontend.send(recv)
                            break

        for thread in threads:
            self.backend.send('__break__')

        for thread in threads:
            thread.join()

        self.frontend.close()
        self.backend.close()
        self.ctx.term()

    def stop(self):
        self._run = False
        time.sleep(1)

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
                msg_id, msg = self._recv(socket)
            except MessageRecvError:
                increment_stat('received_messages')
                increment_stat('malicious_messages')
                continue
            except RoutineStop:
                break

            increment_stat('received_messages')

            try:
                msg = msgpack.unpackb(msg)
                log.debug('Received message: {}'.format(msg))
            except:
                log.warn('Message unpack failed')
                increment_stat('malicious_messages')
                # do not bother to reply if client sent some trash
                continue

            try:
                method = self.methods.get(msg['_method'])
                if (
                    method is None and
                    hasattr(self._default_method, '__call__')
                ):
                    rep = {
                        '_result': self._default_method(
                            msg['_method'],
                            *msg.get('args', ()),
                            **msg.get('kwargs', {})
                        )
                    }
                elif method is not None:
                    rep = {'_result': method(*msg.get('args', ()),
                                             **msg.get('kwargs', {}))}
                else:
                    raise KeyError
                if msg.get('_noreply') == 1:
                    increment_stat('processed_messages')
                    continue
            except Exception, e:
                increment_stat('exceptions')
                rep = {
                    '_error': 50,
                    '_exc_msg': e.message if hasattr(e, 'message') else '',
                    '_traceback': traceback.format_exc(),
                }
                log.error(rep['_exc_msg'], exc_info=sys.exc_info())
                if msg.get('_noreply') == 1:
                    continue

            rep['_uid'] = msg['_uid']

            log.info('Sending reply: {}'.format(rep))
            msg_id, rep = self._prepare_reply(msg_id, rep)
            for part in msg_id:
                socket.send(part, zmq.SNDMORE)
            socket.send(rep)
            increment_stat('processed_messages')

        socket.close()

    def _bind(self):
        self.ctx = zmq.Context()
        self.frontend = self.ctx.socket(zmq.ROUTER)

        try:
            self.frontend.bind(self.bind_uri)
            log.info('Servant listening at {}'.format(self.bind_uri))
        except zmq.error.ZMQError as e:
            exc = ServantBindError(
                'Cannot bind to {}'
                .format(self.bind_uri, e.strerror)
            )
            log.exception(exc)
            raise exc

        self.backend = self.ctx.socket(zmq.DEALER)
        self.backend.bind(self.backend_uri)

    def _recv(self, socket):
        msg_id = []
        while True:
            recv = socket.recv()
            if recv == '__break__':
                raise RoutineStop()
            if socket.getsockopt(zmq.RCVMORE):
                msg_id.append(recv)
            else:
                msg = recv
                return msg_id, msg

    def _prepare_reply(self, msg_id, rep):
        return msg_id, msgpack.packb(rep)


class SecureServant(Servant):

    def __init__(self, secret_key, methods=None,
                 threads_num=DEFAULT_THREADS_NUM):
        super(SecureServant, self).__init__(methods, threads_num)
        self.cipher = AESCipher(secret_key)

    def _recv(self, socket):
        msg_id, msg = super(SecureServant, self)._recv(socket)
        dec_msg = self.cipher.decrypt(msg)
        return msg_id, dec_msg

    def _prepare_reply(self, msg_id, rep):
        msg_id, rep = super(SecureServant, self)._prepare_reply(msg_id, rep)
        return msg_id, self.cipher.encrypt(rep)


class SecureServantIdent(Servant):

    def __init__(self, get_key_fn, methods=None,
                 threads_num=DEFAULT_THREADS_NUM):
        super(SecureServantIdent, self).__init__(methods, threads_num)
        self._ciphers = {}  # cipher per ident
        self._msg_id_to_ident = {}
        self._get_key_fn = get_key_fn
        self._lock = Lock()

    def _recv(self, socket):
        msg_id, orig_msg = super(SecureServantIdent, self)._recv(socket)
        ident = orig_msg[:32]
        msg = orig_msg[32:]
        if ident not in self._ciphers:
            key = self._get_key_fn(ident)
            if key is None:
                return msg_id, orig_msg
            else:
                self._ciphers[ident] = AESCipher(self._get_key_fn(ident))

        self._lock.acquire()
        self._msg_id_to_ident[self._msg_id_hash(msg_id)] = ident
        self._lock.release()

        dec_msg = self._ciphers[ident].decrypt(msg)
        return msg_id, dec_msg

    def _prepare_reply(self, msg_id, rep):
        msg_id, rep = (
            super(SecureServantIdent, self)
            ._prepare_reply(msg_id, rep)
        )
        self._lock.acquire()
        ident = self._msg_id_to_ident.pop(self._msg_id_hash(msg_id))
        self._lock.release()
        return msg_id, self._ciphers[ident].encrypt(rep)

    def _msg_id_hash(self, msg_id):
        return hash(frozenset(msg_id))
