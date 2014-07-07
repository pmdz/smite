import time
import threading
import traceback
import logging
import inspect
import uuid
import sys
from types import ModuleType

import zmq
import zmq.auth
import msgpack
from zmq.auth.thread import ThreadAuthenticator
from zope.dottedname.resolve import resolve

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

    def __init__(self, handlers=None, threads_num=DEFAULT_THREADS_NUM):
        self._handlers = {
            '__echo__': lambda n: n,
            '__default__': None,
        }

        if isinstance(handlers, (list, tuple)):
            map(self.register_handler, handlers)

        elif isinstance(handlers, dict):
            for name, handler in handlers.iteritems():
                self.register_handler(handler, name)

        elif handlers is not None:
            raise ValueError('Invalid \'messages\' argument type: {}'
                             .format(type(handlers)))

        self.threads_num = threads_num
        self.backend_uri = ('inproc://smite-backend-{}'
                            .format(uuid.uuid1().hex))
        self.stats = {'threads': {}, 'summary': _STATS_TMPL.copy()}
        self._lock = threading.Lock()
        self._security_enabled = False

    def enable_security(self, public_keys_dir, server_secret_file):
        self._public_keys_dir = public_keys_dir
        self._server_secret_file = server_secret_file
        self._security_enabled = True

    def set_opts(self, threads_num=None):
        self.threads_num = threads_num | self.threads_num

    def register_handler(self, handler, name=None):
        if not callable(handler):
            raise ValueError('{} is not callable'.format(handler))

        if name is None:
            if inspect.isfunction(handler):
                name = handler.__name__
            elif hasattr(handler, '__class__'):
                name = handler.__class__.__name__

        if name in self._handlers and name != '__default__':
            raise ValueError('Method named \'{}\' is already registered'
                             .format(name))

        self._handlers[name] = handler

    def set_default_handler(self, handler):
        self.register_handler(handler, '__default__')

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
            self.register_handler(fn, '{}.{}'.format(module.__name__, fname))

    def bind(self, bind_uri):
        self.bind_uri = bind_uri
        self._bind()

    def bind_tcp(self, host, port):
        self.bind_uri = 'tcp://{}:{}'.format(host, port)
        self._bind()

    def bind_ipc(self, address):
        self.bind_uri = 'ipc://{}'.format(address)
        self._bind()

    def run(self, run_in_background=False):
        self._running_in_background = run_in_background
        self._stop_event = threading.Event()
        self._worker_threads = []  # list of running threads
        for i in xrange(self.threads_num):
            worker = threading.Thread(target=self._worker_routine)
            worker.daemon = True
            worker.start()
            self.stats['threads'][worker.name] = _STATS_TMPL.copy()
            self._worker_threads.append(worker)

        if run_in_background:
            self._main_thread = threading.Thread(target=self._main_routine)
            self._main_thread.daemon = True
            self._main_thread.start()
        else:
            self._main_routine()

    def _main_routine(self):
        poll = zmq.Poller()
        poll.register(self.frontend, zmq.POLLIN)
        poll.register(self.backend,  zmq.POLLIN)

        while not self._stop_event.is_set():
            sockets = dict(poll.poll(1000))

            if self.frontend in sockets:
                log.debug('recv frontend')
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

        for _ in self._worker_threads:
            self.backend.send('__break__')

        for worker in self._worker_threads:
            worker.join()

        self.frontend.setsockopt(zmq.LINGER, 0)
        self.frontend.close()
        self.backend.setsockopt(zmq.LINGER, 0)
        self.backend.close()
        if self._security_enabled:
            self._auth.stop()
            del self._auth
        self.ctx.term()

    def stop(self):
        self._stop_event.set()
        while not self.ctx.closed:
            time.sleep(.2)
        if self._running_in_background:
            self._main_thread.join()
        del self.ctx, self.frontend, self.backend

    def _worker_routine(self):
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
                handler = self._handlers.get(msg['nm'])
                if handler is None:
                    handler = self._handlers['__default__']

                if handler is None:
                    raise KeyError
                else:
                    args = msg.get('args', ())
                    kw = msg.get('kw', {})
                    reply = {'res': handler(*args, **kw)}
                    del args, kw

                if msg.get('nrep') == 1:
                    increment_stat('processed_messages')
                    continue

            except Exception, e:
                increment_stat('exceptions')
                reply = {
                    'err': 50,
                    'excmsg': e.message if hasattr(e, 'message') else '',
                    'tb': traceback.format_exc(),
                }
                log.error(reply['excmsg'], exc_info=sys.exc_info())
                if msg.get('nrep') == 1:
                    continue

            log.info('Sending reply: {}'.format(reply))
            reply = msgpack.packb(reply)

            for part in msg_id:
                socket.send(part, zmq.SNDMORE)

            socket.send(reply)
            increment_stat('processed_messages')

        # cleanup
        socket.setsockopt(zmq.LINGER, 5)
        socket.close()
        del socket

    def _bind(self):
        self.ctx = zmq.Context()
        self.frontend = self.ctx.socket(zmq.ROUTER)

        if self._security_enabled:
            self._start_auth()
            self._load_certs(
                self._public_keys_dir,
                self._server_secret_file,
            )

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

    def _start_auth(self):
        auth = ThreadAuthenticator(self.ctx)
        auth.start()
        auth.configure_curve(domain='*', location=self._public_keys_dir)
        self._auth = auth

    def _load_certs(self, public_keys_dir, server_secret_file):
        server_public, server_secret = (
            zmq.auth.load_certificate(self._server_secret_file)
        )
        self.frontend.curve_secretkey = server_secret
        self.frontend.curve_publickey = server_public
        self.frontend.curve_server = True
