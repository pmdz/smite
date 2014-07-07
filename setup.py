from setuptools import setup


requires = [
    'msgpack-python==0.4.2',
    'pyzmq==14.3.0',
    'zope.dottedname==4.0.1',
]


setup(
    name='smite',
    packages=['smite'],
    version='0.2a2',
    install_requires=requires,
    author='pmdez',
    author_email='pawel@mewritescode.com',
    url='https://github.com/pmdz/smite',
    zip_safe=False,
    description='Simple RPC-like messaging library based on ZMQ',
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
    ],
    entry_points={
        'console_scripts': [
            'smite-create-certificates = smite.cli:create_certificates',
        ],
    }
)
