# -*- coding: utf-8 -*-
import logging

import zmq

from smite.exceptions import ProxyBindError


log = logging.getLogger('smite.proxy')


class Proxy(object):
    def __init__(self, pass_host, pass_port):
        self.pass_uri = 'tcp://{}:{}'.format(pass_host, pass_port)

    def bind(self, host, port):
        frontend_uri = 'tcp://{}:{}'.format(host, port)

        self.ctx = zmq.Context()

        self.frontend = self.ctx.socket(zmq.ROUTER)
        try:
            self.frontend.bind(frontend_uri)
            log.debug('proxy listening on {}'.format(frontend_uri))
        except zmq.error.ZMQError as e:
            exc = ProxyBindError(
                'Cannot bind to {} ({})'
                .format(frontend_uri, e.strerror)
            )
            log.exception(exc)
            raise exc

        self.backend = self.ctx.socket(zmq.DEALER)
        try:
            self.backend.connect(self.pass_uri)
            log.debug('proxy forwarding to {}'.format(self.pass_uri))
        except zmq.error.ZMQError as e:
            exc = ProxyBindError(
                'Cannot bind to {} ({})'
                .format(self.pass_uri, e.strerror)
            )
            log.exception(exc)
            raise exc

    def run(self):
        self._run = True

        poll = zmq.Poller()
        poll.register(self.frontend, zmq.POLLIN)
        poll.register(self.backend,  zmq.POLLIN)

        while self._run:
            sockets = dict(poll.poll(1000))
            log.debug(sockets)

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

        self.frontend.close()
        self.backend.close()
        self.ctx.term()

    def stop(self):
        self._run = False
