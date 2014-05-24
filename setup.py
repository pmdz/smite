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
    author='pmdez',
    author_email='pawel@mewritescode.com',
    url='https://github.com/pmdz/smite',
    zip_safe=False,
    description='Simple messaging library based on ZMQ',
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
    ],
    entry_points={
        'console_scripts': [
            'smite-servant = smite.cli.servant:main',
        ],
    }
)
