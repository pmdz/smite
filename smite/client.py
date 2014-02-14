import uuid
import logging

import zmq
import msgpack

from smite.message import Message
from smite.aes_cipher import AESCipher
from smite.exceptions import (
    ConnectionError,
    ClientTimeout,
    MessageException,
)

log = logging.getLogger('smite.client')


class Client(object):

    def __init__(self, host, port, secret_key=None, default_timeout=5):
        self.host = host
        self.port = port
        self._default_timeout = default_timeout
        self.cipher = AESCipher(secret_key) if secret_key is not None else None

        self.ctx = zmq.Context()
        self._create_socket()

    def send(self, msg, timeout=None):
        if not isinstance(msg, Message):
            raise TypeError('\'msg\' argument should be type of \'Message\'')
        if timeout is None:
            timeout = self._default_timeout

        msg = {
            '_method': msg.method,
            '_uid': uuid.uuid4().hex,
            'args': msg.args,
            'kwargs': msg.kwargs,
        }
        log.debug('Sending message: {}'.format(msg))

        msg = msgpack.packb(msg)

        if self.cipher is not None:
            msg = self.cipher.encrypt(msg)

        self._socket.send(msg)
        sockets = dict(self._poll.poll(timeout * 1000))

        if sockets.get(self._socket) == zmq.POLLIN:
            rep = self._socket.recv()
            if self.cipher is not None:
                rep = self.cipher.decrypt(rep)
            rep = msgpack.unpackb(rep)
            # TODO: check reply uid and raise exc eventually
            if '_error' in rep:
                if rep['_error'] == 50:
                    log.error(rep['_traceback'])
                    raise MessageException(rep['_exc_msg'], rep['_traceback'])
        else:
            log.error('Message timeout ({} sec) reached -> recreating socket'
                      .format(timeout))
            self._socket.setsockopt(zmq.LINGER, 0)
            self._socket.close()
            self._poll.unregister(self._socket)
            self._create_socket()
            raise ClientTimeout

        return rep['_result']

    def _create_socket(self):
        self._socket = self.ctx.socket(zmq.DEALER)
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
