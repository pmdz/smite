from setuptools import setup


requires = [
    'psutil==1.2.1',
    'pycrypto==2.6.1',
    'msgpack-python==0.4.0',
    'pyzmq==14.3.0',
    'zope.dottedname==4.0.1',
]


setup(
    name='smite',
    packages=['smite'],
    version='0.1a6',
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
