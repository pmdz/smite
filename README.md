Smite
=====

Simple RPC-like messaging library based on ZMQ

Basic example
-------------

```python
import smite

host = '127.0.0.1'
port = 3000

def echo(text):
    return text

servant = smite.Servant(handlers={'echo': echo})
servant.bind_tcp(host, port)
servant.run()

client = smite.Client()
client.connect_tcp(host, port)
client.send(msg_name='echo', args=('foobar',))

```
