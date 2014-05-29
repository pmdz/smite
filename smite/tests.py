import uuid
import time
import random
from threading import Thread

import zmq

from smite.message import Message
from smite.servant import (
    Servant,
    SecureServant,
    SecureServantIdent,
)
from smite.client import Client
from smite.proxy import Proxy
from smite.exceptions import (
    ClientTimeout,
    MessageException,
)


HOST = '127.0.0.1'
PORT = 3000
CONNECTION_URI = 'tcp://{}:{}'.format(HOST, PORT)


def client_timeout():
    timeout = 3

    client = Client(default_timeout=timeout)
    client.connect(CONNECTION_URI)
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
    servant.bind_tcp(HOST, PORT)
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


def test_noreply_message():
    servant = Servant({'echo': lambda t: t})
    servant.bind_tcp(HOST, PORT)

    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client()
    client.connect(CONNECTION_URI)
    msg = Message('echo', uuid.uuid1().hex)
    client.send(msg, noreply=True)

    time.sleep(1)
    assert servant.stats['summary']['received_messages'] == 1
    assert servant.stats['summary']['processed_messages'] == 1

    servant.stop()
    servant_thread.join()


def test_multiple_clients():

    def short_echo(text):
        time.sleep(1)
        return text

    def long_echo(text):
        time.sleep(2)
        return text

    servant = Servant({'short_echo': short_echo, 'long_echo': long_echo})
    servant.bind_tcp(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    class send_msg(object):
        def __init__(self, method_name):
            self.method_name = method_name

        def __call__(self):
            client = Client()
            client.connect(CONNECTION_URI)
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


def test_proxy():
    host = '127.0.0.1'
    proxy_port = '9000'
    servant_port = '9001'

    def echo(text):
        return text

    servant = Servant({'echo': echo})
    servant.bind_tcp(host, servant_port)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    proxy = Proxy(host, servant_port)
    proxy.bind(host, proxy_port)
    proxy_thread = Thread(target=proxy.run)
    proxy_thread.start()

    class send_msg(object):
        def __init__(self, method_name):
            self.method_name = method_name

        def __call__(self):
            time.sleep(.3)
            client = Client()
            client.connect_tcp(host, proxy_port)
            txt = uuid.uuid4().hex
            msg = Message(self.method_name, txt)
            res = client.send(msg)
            assert res == txt

    messages_num = 10
    client_threads = []
    for i in xrange(messages_num):
        thread = Thread(target=send_msg('echo'))
        client_threads.append(thread)
        thread.start()

    time.sleep(1)

    assert servant.stats['summary']['received_messages'] == messages_num
    assert servant.stats['summary']['processed_messages'] == messages_num
    assert servant.stats['summary']['exceptions'] == 0

    servant.stop()
    servant_thread.join()
    proxy.stop()
    proxy_thread.join()


def test_exception_response():
    exc_message = 'This is dummy exception message'

    class DummyException(Exception):
        pass

    def raise_dummy_exc():
        raise DummyException(exc_message)

    servant = Servant({'raise_dummy_exc': raise_dummy_exc})
    servant.bind_tcp(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client()
    client.connect(CONNECTION_URI)

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

    servant = SecureServant(methods=[multipl], secret_key=secret)
    servant.bind_tcp(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(secret_key=secret)
    client.connect_tcp(HOST, PORT)
    rep = client.send(Message('multipl', 2, 4))
    assert rep == 8

    servant.stop()
    servant_thread.join()


def test_secure_servant_ident():
    secrets = {
        '38dce0e1b46d4ae089c6d425653b57a9': '1234s9v02',
        'cbe74d25f5764dd8955d4ec137b7de4a': '95nx84mxw',
        '663d817ba3bf4fa6a8f4214c78621294': '4n9t7us7l',
    }

    def get_key(ident):
        return secrets[ident]

    def multipl(num1, num2):
        return num1 * num2

    servant = SecureServantIdent(
        get_key_fn=get_key,
        methods=[multipl],
    )
    servant.bind_tcp(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    def send_messages(secret_key, ident):
        client = Client(secret_key=secret_key, ident=ident)
        client.connect(CONNECTION_URI)
        for i in range(50):
            a = random.randint(1, 10)
            b = random.randint(1, 10)
            expected_result = multipl(a, b)
            rep = client.send(Message('multipl', a, b))
            assert rep == expected_result

    client_threads = []
    for ident, key in secrets.items():
        thread = Thread(target=send_messages, args=(key, ident))
        client_threads.append(thread)
        thread.start()

    time.sleep(1)
    for t in client_threads:
        t.join()

    servant.stop()
    servant_thread.join()


def test_malicious_messages_non_secure():

    def echo(text):
        return text

    servant = Servant([echo])
    servant.bind_tcp(HOST, PORT)
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

    servant = SecureServant(methods=[echo], secret_key=secret_1)
    servant.bind_tcp(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(secret_key=secret_2)
    client.connect(CONNECTION_URI)
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
