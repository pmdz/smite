Smite
=====

Little messaging library built on top of ZeroMQ

```python
import smite

host = '127.0.0.1'
port = 3000

def echo(text):
    return text

servant = smite.Servant(methods={'echo': echo})
servant.bind(host, port)
servant.run()

client = smite.Client(host, port)
msg = smite.Message('echo', 'foo')
reply = client.send(msg)  # 'foo'
```
