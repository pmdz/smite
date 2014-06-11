# -*- coding: utf-8 -*-
import os
import sys

from smite import utils


def create_certificates(argv=sys.argv):

    if len(argv) < 3:
        cmd = os.path.basename(argv[0])
        print(
            u'usage: {0} <KEYS_DIR> <NAME>\n'
            u'(example: "{0} /home/user/keys/ my_secret")'
            .format(cmd)
        )
        sys.exit(1)

    keys_dir = argv[1]
    name = argv[2]

    if not os.path.exists(keys_dir):
        print(u'Dir not exists: {}'.format(keys_dir))
        sys.exit(1)

    if not os.path.isdir(keys_dir):
        print(u'\'{}\' is noot directory: {}'.format(keys_dir))
        sys.exit(1)

    utils.create_certificates(keys_dir, name)
