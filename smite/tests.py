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
