import uuid

import zmq
import msgpack

from smite.message import Message
from smite.aes_cipher import AESCipher
from smite.exceptions import (
    ConnectionError,
    ClientTimeout,
)


class Client(object):

    def __init__(self, host, port, identity=None, secret_key=None, default_timeout=5):
        self.host = host
        self.port = port
        self._default_timeout = default_timeout

        if identity is not None and secret_key is not None:
            self._identity = self.cipher.encrypt(identity)
        elif identity is not None:
            self._identity = identity
        elif identity is None:
            self._identity = str(uuid.uuid1())

        self.ctx = zmq.Context()
        self._create_socket()
        if secret_key is not None:
            self.cipher = AESCipher(secret_key)
        else:
            self.cipher = None

    def send(self, msg, timeout=None):
        if timeout is None:
            timeout = self._default_timeout
        if not isinstance(msg, Message):
            raise TypeError('\'msg\' argument should be type of \'Message\'')

        msg = {
            '_method': msg.method,
            'arg': msg.args,
            'kw': msg.kwargs,
        }

        msg = msgpack.packb(msg)

        if self.cipher is not None:
            msg = self.cipher.encrypt(msg)

        self._socket.send(msg)
        sockets = dict(self._poll.poll(timeout * 1000))

        if sockets.get(self._socket) == zmq.POLLIN:
            rep = self._socket.recv()
            if self.cipher is not None:
                rep = self.cipher.encrypt(rep)
            rep = msgpack.unpackb(rep)
        else:
            self._socket.setsockopt(zmq.LINGER, 0)
            self._socket.close()
            self._poll.unregister(self._socket)
            self._create_socket()
            raise ClientTimeout

        return rep

    def _create_socket(self):
        self._socket = self.ctx.socket(zmq.DEALER)
        self._socket.setsockopt(zmq.IDENTITY, self._identity)
        self._poll = zmq.Poller()
        self._poll.register(self._socket, zmq.POLLIN)
        try:
            connection_uri = 'tcp://{}:{}'.format(self.host, self.port)
            self._socket.connect(connection_uri)
        except Exception as e:
            raise ConnectionError(
                'Could not connect to: {} ({})'
                .format(connection_uri, e.message)
            )
