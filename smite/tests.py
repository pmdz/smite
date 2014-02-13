import uuid
import time
from threading import Thread

import zmq

from smite.message import Message
from smite.servant import (
    Servant,
    SecureServant,
)
from smite.client import Client
from smite.exceptions import (
    ClientTimeout,
    MessageException,
)


HOST = '127.0.0.1'
PORT = 3000


def test_client_timeout():
    timeout = 3

    client = Client(HOST, PORT, default_timeout=timeout)
    msg = Message('dummy_method')

    raised = False
    start = time.time()
    try:
        client.send(msg)
    except ClientTimeout:
        raised = True

    assert raised

    # it should take around 3 seconds
    assert 2.5 < time.time() - start < 3.5

    # servant should not get this message after start, it's just gone
    class DummyException(Exception):
        pass

    def dummy_method():
        raise DummyException

    servant = Servant({'dummy_method': dummy_method})
    servant.bind(HOST, PORT)
    # run servant in separate thread and wait 3 seconds for message
    servant_thread = Thread(target=servant.run)
    servant_thread.start()
    time.sleep(3)
    servant.stop()
    servant_thread.join()

    for thread_stats in servant.stats['threads'].values():
        assert thread_stats['exceptions'] == 0
        assert thread_stats['received_messages'] == 0
        assert thread_stats['malicious_messages'] == 0
        assert thread_stats['processed_messages'] == 0

    assert servant.stats['summary']['exceptions'] == 0
    assert servant.stats['summary']['received_messages'] == 0
    assert servant.stats['summary']['malicious_messages'] == 0
    assert servant.stats['summary']['processed_messages'] == 0


def test_multiple_clients():

    def short_echo(text):
        time.sleep(1)
        return text

    def long_echo(text):
        time.sleep(2)
        return text

    servant = Servant({'short_echo': short_echo, 'long_echo': long_echo})
    servant.bind(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    class send_msg(object):
        def __init__(self, method_name):
            self.method_name = method_name

        def __call__(self):
            client = Client(HOST, PORT)
            txt = uuid.uuid4().hex
            msg = Message(self.method_name, txt)
            res = client.send(msg)
            assert res == txt

    client_threads = []
    for method_name in ['short_echo', 'long_echo']:
        thread = Thread(target=send_msg(method_name))
        client_threads.append(thread)
        thread.start()

    # long echo takes 2 seconds
    time.sleep(2.5)

    assert servant.stats['summary']['received_messages'] == 2
    assert servant.stats['summary']['processed_messages'] == 2
    assert servant.stats['summary']['exceptions'] == 0

    servant.stop()
    servant_thread.join()

    for client_thread in client_threads:
        client_thread.join()


def test_exception_response():
    exc_message = 'This is dummy exception message'

    class DummyException(Exception):
        pass

    def raise_dummy_exc():
        raise DummyException(exc_message)

    servant = Servant({'raise_dummy_exc': raise_dummy_exc})
    servant.bind(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(HOST, PORT)

    raised = False
    try:
        client.send(Message('raise_dummy_exc'))
    except MessageException, e:
        assert e.message == exc_message
        raised = True

    assert raised

    time.sleep(.1)
    assert servant.stats['summary']['received_messages'] == 1
    assert servant.stats['summary']['exceptions'] == 1
    servant.stop()
    servant_thread.join()


def test_encrypted_messaging():
    secret = 'foobar'

    def multipl(num1, num2):
        return num1 * num2

    servant = SecureServant([multipl], secret)
    servant.bind(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(HOST, PORT, secret_key=secret)
    rep = client.send(Message('multipl', 2, 4))
    assert rep == 8

    servant.stop()
    servant_thread.join()


def test_malicious_messages_non_secure():

    def echo(text):
        return text

    servant = Servant([echo])
    servant.bind(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    ctx = zmq.Context()

    socket = ctx.socket(zmq.DEALER)
    poll = zmq.Poller()
    poll.register(socket, zmq.POLLIN)
    socket.connect('tcp://{}:{}'.format(HOST, PORT))

    socket.send('foo')

    sockets = dict(poll.poll(2000))
    assert sockets.get(socket) != zmq.POLLIN

    time.sleep(.2)
    assert servant.stats['summary']['received_messages'] == 1
    assert servant.stats['summary']['processed_messages'] == 0
    assert servant.stats['summary']['malicious_messages'] == 1

    servant.stop()
    servant_thread.join()


def test_malicious_messages_secure():
    secret_1 = 'foo'
    secret_2 = 'bar'

    def echo(text):
        return text

    servant = SecureServant([echo], secret_key=secret_1)
    servant.bind(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(HOST, PORT, secret_key=secret_2)
    raised = False
    try:
        client.send(Message('multipl', 2, 4), 2)
    except ClientTimeout:
        raised = True

    assert raised

    time.sleep(.2)
    assert servant.stats['summary']['received_messages'] == 1
    assert servant.stats['summary']['processed_messages'] == 0
    assert servant.stats['summary']['malicious_messages'] == 1

    servant.stop()
    servant_thread.join()
