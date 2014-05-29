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

    def __init__(self, secret_key=None, ident=None,
                 default_timeout=5):
        self.ident = ident
        self._default_timeout = default_timeout
        self.cipher = AESCipher(secret_key) if secret_key is not None else None
        self._uuid_node = uuid.getnode()

    def connect(self, connection_uri):
        self.connection_uri = connection_uri
        self._connect()

    def connect_tcp(self, host, port):
        self.connection_uri = 'tcp://{}:{}'.format(host, port)
        self._connect()

    def connect_inproc(self, address):
        self.connection_uri = 'inproc://{}'.format(address)
        self._connect()

    def connect_ipc(self, address):
        self.connection_uri = 'ipc://{}'.format(address)
        self._connect()

    def send(self, msg, timeout=None, noreply=False):
        return self._send(msg, timeout=None, noreply=False)

    def _send(self, msg, timeout=None, noreply=False):
        if not isinstance(msg, Message):
            raise TypeError('\'msg\' argument should be type of \'Message\'')
        if timeout is None:
            timeout = self._default_timeout

        msg_d = {
            '_method': msg.method,
            '_uid': uuid.uuid1(self._uuid_node).hex,
        }
        if noreply:
            msg_d['_noreply'] = 1
        if msg.args:
            msg_d['args'] = msg.args
        if msg.kwargs:
            msg_d['kwargs'] = msg.kwargs

        msg = msg_d
        del msg_d

        log.debug('Sending message: {}'.format(msg))

        msg = msgpack.packb(msg)

        if self.cipher is not None:
            msg = self.cipher.encrypt(msg)

        if self.ident is not None:
            msg = '{}{}'.format(self.ident, msg)
        self._socket.send(msg)

        if noreply:
            return True
        else:
            return self._wait_for_reply(timeout)

    def _connect(self):
        self.ctx = zmq.Context()
        self._create_socket()

    def _wait_for_reply(self, timeout):
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
            self._socket.connect(self.connection_uri)
        except Exception as e:
            raise ConnectionError(
                'Could not connect to: {} ({})'
                .format(self.connection_uri, e.message)
            )


class RClient(Client):

    def send(self, msg_name, *args, **kw):
        msg = Message(msg_name, *args, **kw)
        return self._send(msg)

    def send_noreply(self, msg_name, *args, **kw):
        msg = Message(msg_name, *args, **kw)
        return self._send(msg, noreply=True)
