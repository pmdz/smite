import logging

import zmq
import zmq.auth
import msgpack

from smite.exceptions import (
    ConnectionError,
    ClientTimeout,
    MessageException,
)

log = logging.getLogger('smite.client')


class Client(object):

    def __init__(self, default_timeout=5):
        self._default_timeout = default_timeout
        self._security_enabled = False

    def enable_security(self, client_secret_file, server_public_file):
        self._client_secret_file = client_secret_file
        self._server_public_file = server_public_file
        self._security_enabled = True

    def connect(self, connection_uri):
        self.connection_uri = connection_uri
        self._connect()

    def connect_tcp(self, host, port):
        self.connection_uri = 'tcp://{}:{}'.format(host, port)
        self._connect()

    def connect_ipc(self, address):
        self.connection_uri = 'ipc://{}'.format(address)
        self._connect()

    def close(self, linger=5):
        # linger (miliseconds) specifies how long context will wait
        # for delivering all pending messages
        self._socket.setsockopt(zmq.LINGER, linger)
        self._socket.close()
        self.ctx.term()
        del self.ctx, self._socket  # cleanup

    def send(self, msg_name, args=None, kwargs=None, timeout=None,
             noreply=False):

        if not hasattr(self, 'ctx'):
            raise RuntimeError('Client is not connected')

        if msg_name.startswith('__') and msg_name.endswith('__'):
            raise ValueError('Inappropriate message name: {}'.format(msg_name))

        msg = {'nm': msg_name}

        if isinstance(args, (list, tuple)):
            msg['args'] = args
        elif args is not None:
            raise ValueError('args has to be list or tuple')

        if isinstance(kwargs, dict):
            msg['kw'] = kwargs
        elif kwargs is not None:
            raise ValueError('kwargs has to be a dict')

        if timeout is None:
            timeout = self._default_timeout

        if noreply:
            msg['nrep'] = 1

        log.debug('Sending message: {}'.format(msg))

        msg = msgpack.packb(msg)
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
            reply = self._socket.recv()
            reply = msgpack.unpackb(reply)
            if 'err' in reply:
                if reply['err'] == 50:
                    log.error(reply['tb'])
                    raise MessageException(
                        reply['excmsg'],
                        reply['tb']
                    )
        else:
            log.error('Message timeout ({} sec) reached -> recreating socket'
                      .format(timeout))
            self._socket.setsockopt(zmq.LINGER, 0)
            self._socket.close()
            self._poll.unregister(self._socket)
            self._create_socket()
            raise ClientTimeout

        return reply['res']

    def _create_socket(self):
        self._socket = self.ctx.socket(zmq.DEALER)
        self._poll = zmq.Poller()
        self._poll.register(self._socket, zmq.POLLIN)
        if self._security_enabled:
            self._load_certs()
        try:
            self._socket.connect(self.connection_uri)
        except Exception as e:
            raise ConnectionError(
                'Could not connect to: {} ({})'
                .format(self.connection_uri, e.message)
            )

    def _load_certs(self):
        client_public, client_secret = (
            zmq.auth.load_certificate(self._client_secret_file)
        )
        self._socket.curve_secretkey = client_secret
        self._socket.curve_publickey = client_public

        server_public, _ = zmq.auth.load_certificate(self._server_public_file)
        self._socket.curve_serverkey = server_public


class RClient(Client):

    def __init__(self, connection_uri, default_timeout=5):
        super(RClient, self).__init__(default_timeout)
        self.connection_uri = connection_uri
        self._connect()

    def send(self, __msg_name, *args, **kwargs):
        return super(RClient, self).send(__msg_name, args, kwargs)

    def send_noreply(self, __msg_name, *args, **kwargs):
        return super(RClient, self).send(
            __msg_name, args, kwargs, noreply=True
        )
