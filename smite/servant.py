import time
import threading
import traceback

import zmq
import msgpack

from smite.aes_cipher import AESCipher
from smite.exceptions import ServantBindError


DEFAULT_THREADS_NUM = 5

_STATS_TMPL = {
    'received_messages': 0,
    'processed_messages': 0,
    'malicious_messages': 0,
    'exceptions': 0,
}


class Servant(object):

    def __init__(self, methods, threads_num=DEFAULT_THREADS_NUM):
        self.methods = methods
        self.threads_num = threads_num
        self.backend_uri = 'inproc://smite-backend'
        self.stats = {'threads': {}, 'summary': _STATS_TMPL.copy()}
        self._lock = threading.Lock()

    def set_opts(self, threads_num=None):
        self.threads_num = threads_num | self.threads_num

    def bind(self, host, port):
        self.ctx = zmq.Context()
        self.frontend = self.ctx.socket(zmq.ROUTER)

        try:
            self.frontend.bind('tcp://{}:{}'.format(host, port))
        except zmq.error.ZMQError as e:
            raise ServantBindError(
                'Cannot bind to {}:{} ({})'
                .format(host, port, e.strerror)
            )

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
            id_ = socket.recv()
            if id_ == '__break__':
                break
            msg = socket.recv()

            with self._lock:
                increment_stat('received_messages')

            try:
                msg = self._process_message(msg)
            except:
                increment_stat('malicious_messages')
                # do not bother to reply if client sent some trash
                continue

            try:
                method = self.methods[msg['_method']]
                rep = {'_result': method(*msg['args'], **msg['kwargs'])}
            except Exception:
                increment_stat('exceptions')
                rep = {'_error': 50, '_traceback': traceback.format_exc()}

            rep['_uid'] = msg['_uid']

            socket.send(id_, zmq.SNDMORE)
            socket.send(self._process_reply(rep))
            increment_stat('processed_messages')

        socket.close()

    def _process_message(self, msg):
        return msgpack.unpackb(msg)

    def _process_reply(self, rep):
        return msgpack.packb(rep)


class SecureServant(Servant):

    def __init__(self, methods, secret_key, threads_num=DEFAULT_THREADS_NUM):
        super(SecureServant, self).__init__(methods, threads_num)
        self.cipher = AESCipher(secret_key)

    def _process_message(self, msg):
        return msgpack.unpackb(self.cipher.decrypt(msg))

    def _process_reply(self, rep):
        return self.cipher.encrypt(msgpack.packb(rep))
