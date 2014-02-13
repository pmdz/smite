from setuptools import setup


requires = [
    'psutil==1.2.1',
    'pycrypto==2.6.1',
    'msgpack-python==0.4.0',
    'pyzmq==14.0.1',
    'zope.dottedname==4.0.1',
]


setup(
    name='smite',
    version='0.1a',
    install_requires=requires,
)
