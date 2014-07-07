import os
import uuid
import time
import random
from threading import Thread
from string import ascii_lowercase

import zmq

from smite import (
    Client,
    RClient,
    Servant,
    Proxy,
    utils,
)
from smite.exceptions import (
    ClientTimeout,
    MessageException,
)


HOST = '127.0.0.1'
PORT = 3000
CONNECTION_URI = 'tcp://{}:{}'.format(HOST, PORT)


def create_keys_dir():
    rnd_str = ''.join([random.choice(ascii_lowercase) for _ in range(10)])
    dir_ = '/tmp/smite_test_keys_{}'.format(rnd_str)
    os.mkdir(dir_)
    return dir_


def test_client_timeout():
    timeout = 3

    client = Client(default_timeout=timeout)
    client.connect(CONNECTION_URI)

    raised = False
    start = time.time()
    try:
        client.send('dummy_method')
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
    client.close()

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
    client.send('echo', args=(uuid.uuid1().hex,), noreply=True)

    time.sleep(2)
    assert servant.stats['summary']['received_messages'] == 1
    assert servant.stats['summary']['processed_messages'] == 1

    servant.stop()
    servant_thread.join()
    client.close()


def test_rclient():
    ipc_name = 'smite-test-{}'.format(uuid.uuid1().hex)

    servant = Servant({'echo': lambda t: t})
    servant.bind_ipc(ipc_name)
    servant.run(True)

    msg_num = 10

    client = RClient('ipc://{}'.format(ipc_name))
    for _ in range(msg_num):
        echo_txt = uuid.uuid1().hex
        rep = client.send('echo', echo_txt)
        assert rep == echo_txt

    assert servant.stats['summary']['exceptions'] == 0
    assert servant.stats['summary']['malicious_messages'] == 0
    assert servant.stats['summary']['received_messages'] == msg_num
    assert servant.stats['summary']['processed_messages'] == msg_num

    client.close()
    servant.stop()


def test_default_handler():
    ipc_name = 'smite-test-{}'.format(uuid.uuid1().hex)
    default_handler = lambda t: t

    servant = Servant()
    servant.set_default_handler(default_handler)
    servant.bind_ipc(ipc_name)
    servant.run(True)

    msg_num = 10

    client = RClient('ipc://{}'.format(ipc_name))
    for _ in range(msg_num):
        msg_txt = uuid.uuid1().hex
        random_msg_name = uuid.uuid1().hex
        rep = client.send(random_msg_name, msg_txt)
        assert rep == msg_txt

    assert servant.stats['summary']['exceptions'] == 0
    assert servant.stats['summary']['malicious_messages'] == 0
    assert servant.stats['summary']['received_messages'] == msg_num
    assert servant.stats['summary']['processed_messages'] == msg_num

    client.close()
    servant.stop()


def test_rclient_noreply():
    ipc_name = 'smite-test-{}'.format(uuid.uuid1().hex)

    servant = Servant({'echo': lambda t: t})
    servant.bind_ipc(ipc_name)
    servant.run(True)

    msg_num = 10

    client = RClient('ipc://{}'.format(ipc_name))
    for _ in range(msg_num):
        echo_txt = uuid.uuid1().hex
        client.send_noreply('echo', echo_txt)

    time.sleep(1)

    assert servant.stats['summary']['exceptions'] == 0
    assert servant.stats['summary']['malicious_messages'] == 0
    assert servant.stats['summary']['received_messages'] == msg_num
    assert servant.stats['summary']['processed_messages'] == msg_num

    client.close()
    servant.stop()


def test_multiple_clients():

    def short_echo(text):
        time.sleep(1)
        return text

    def long_echo(text):
        time.sleep(2)
        return text

    servant = Servant({'short_echo': short_echo, 'long_echo': long_echo})
    servant.bind_tcp(HOST, PORT)
    servant.run(run_in_background=True)

    class send_msg(object):
        def __init__(self, message_name):
            self.message_name = message_name

        def __call__(self):
            client = Client()
            client.connect(CONNECTION_URI)
            txt = uuid.uuid4().hex
            res = client.send(self.message_name, args=(txt,))
            assert res == txt
            client.close()

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

    for client_thread in client_threads:
        client_thread.join()


def test_inappropriate_message_name():
    raised = False

    client = Client()
    client.connect_ipc('foo')
    try:
        client.send(msg_name='__foo__')
    except ValueError:
        raised = True

    assert raised


def test_client_not_connected():
    raised = False

    client = Client()
    try:
        client.send(msg_name='foo')
    except RuntimeError:
        raised = True

    assert raised


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
        def __init__(self, message_name):
            self.message_name = message_name

        def __call__(self):
            time.sleep(.3)
            client = Client()
            client.connect_tcp(host, proxy_port)
            txt = uuid.uuid4().hex
            res = client.send(self.message_name, args=(txt,))
            assert res == txt
            client.close()

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
    servant.run(True)

    client = Client()
    client.connect(CONNECTION_URI)

    raised = False
    try:
        client.send('raise_dummy_exc')
    except MessageException, e:
        assert e.message == exc_message
        raised = True

    assert raised

    time.sleep(.1)
    assert servant.stats['summary']['received_messages'] == 1
    assert servant.stats['summary']['exceptions'] == 1
    servant.stop()
    client.close()


def test_malicious_messages():

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


def test_secure_messaging():
    keys_dir = create_keys_dir()

    def short_echo(text):
        time.sleep(1)
        return text

    def long_echo(text):
        time.sleep(2)
        return text

    send_msgs = ['short_echo', 'long_echo']

    # generate keys for clients
    client_secrets = [
        utils.create_certificates(keys_dir, 'client-{}'.format(i))[1]
        for i in range(2)
    ]

    # generate keys for servant
    servant_public, servant_secret = (
        utils.create_certificates(keys_dir, 'servant')
    )

    servant = Servant({'short_echo': short_echo, 'long_echo': long_echo})
    servant.enable_security(
        os.path.join(keys_dir, 'public_keys'), servant_secret,
    )
    servant.bind_tcp(HOST, PORT)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    class send_msg(object):
        def __init__(self, message_name, client_secret):
            self.message_name = message_name
            self.client_secret = client_secret

        def __call__(self):
            client = Client()
            client.enable_security(self.client_secret, servant_public)
            client.connect(CONNECTION_URI)
            txt = uuid.uuid4().hex
            res = client.send(self.message_name, args=(txt,))
            assert res == txt
            client.close()

    client_threads = []
    for client_secret, method_name in zip(client_secrets, send_msgs):
        thread = Thread(target=send_msg(method_name, client_secret))
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
