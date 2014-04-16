# -*- coding: utf-8 -*-
import time
import sys
import json
import signal
import threading

from smite.servant import (
    Servant,
    SecureServant,
    DEFAULT_THREADS_NUM
)


def start_servant(config):
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
    servant_thread = threading.Thread(target=servant.run)
    servant_thread.start()
    return servant, servant_thread


def main(argv=sys.argv):
    config_file = argv[1]

    def load_config():
        with open(config_file) as f:
            return json.load(f)

    refs = {}
    refs['servant'], refs['thread'] = start_servant(load_config())

    def handle_sighup(signum, frame):
        refs['servant'].stop()
        refs['thread'].join()
        refs['servant'], refs['thread'] = start_servant(load_config())

    def handle_sigterm(signum, frame):
        refs['servant'].stop()
        refs['thread'].join()

    signal.signal(signal.SIGHUP, handle_sighup)
    signal.signal(signal.SIGTERM, handle_sigterm)

    # catch keyboard interrupt
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handle_sigterm(None, None)
