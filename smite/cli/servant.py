# -*- coding: utf-8 -*-
import sys
import json

from smite.servant import (
    Servant,
    SecureServant,
    DEFAULT_THREADS_NUM
)


def main(argv=sys.argv):
    with open(argv[1]) as f:
        config = json.load(f)

    secret_key = None

    if 'secret_key_file' in config:
        with open(config['secret_key_file']) as f:
            secret_key = f.read().strip()

    elif 'secret_key' in config:
        secret_key = config['secret_key']

    threads_num = config.get('threads_num', DEFAULT_THREADS_NUM)
    if secret_key is not None:
        servant = SecureServant(secret_key, threads_num=threads_num)
    else:
        servant = Servant(threads_num=threads_num)

    expose_modules = config.get('expose_modules', [])
    for module in expose_modules:
        servant.expose_module(module)

    servant.bind(config['host'], config['port'])
    servant.run()
