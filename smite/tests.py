import uuid
import time
from threading import Thread


def test_client_timeout():
    from message import Message
    from servant import Servant
    from client import Client
    from exceptions import ClientTimeout

    host = '127.0.0.1'
    port = 3000
    timeout = 3

    client = Client(host, port, default_timeout=timeout)
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
    servant.bind(host, port)
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


# TODO: restart server during message processing
#   send try later message?

def test_multiple_clients():
    from message import Message
    from servant import Servant
    from client import Client

    host = '127.0.0.1'
    port = 3000

    def short_echo(text):
        time.sleep(1)
        return text

    def long_echo(text):
        time.sleep(2)
        return text

    servant = Servant({'short_echo': short_echo, 'long_echo': long_echo})
    servant.bind(host, port)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    class send_msg(object):
        def __init__(self, method_name):
            self.method_name = method_name

        def __call__(self):
            client = Client(host, port)
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
    from message import Message
    from servant import Servant
    from client import Client
    from exceptions import MessageException

    host = '127.0.0.1'
    port = 3000

    exc_message = 'This is dummy exception message'

    class DummyException(Exception):
        pass

    def raise_dummy_exc():
        raise DummyException(exc_message)

    servant = Servant({'raise_dummy_exc': raise_dummy_exc})
    servant.bind(host, port)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(host, port)

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
    from message import Message
    from servant import SecureServant
    from client import Client

    host = '127.0.0.1'
    port = 3000
    secret = 'foobar'

    def multipl(num1, num2):
        return num1 * num2

    servant = SecureServant([multipl], secret)
    servant.bind(host, port)
    servant_thread = Thread(target=servant.run)
    servant_thread.start()

    client = Client(host, port, secret_key=secret)
    rep = client.send(Message('multipl', 2, 4))
    assert rep == 8

    servant.stop()
    servant_thread.join()
