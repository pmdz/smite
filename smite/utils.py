import os
import shutil
import zmq.auth


def create_certificates(base_dir, name):
    public_file, secret_file = zmq.auth.create_certificates(base_dir, name)

    public_keys_dir = os.path.join(base_dir, 'public_keys')
    secret_keys_dir = os.path.join(base_dir, 'private_keys')

    for d in [public_keys_dir, secret_keys_dir]:
        if not os.path.exists(d):
            os.mkdir(d)

    shutil.move(public_file, public_keys_dir)
    shutil.move(secret_file, secret_keys_dir)
    public_file = os.path.join(public_keys_dir, os.path.basename(public_file))
    secret_file = os.path.join(secret_keys_dir, os.path.basename(secret_file))
    return public_file, secret_file
