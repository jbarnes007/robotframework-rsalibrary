from setuptools import setup
from os.path import join, dirname

execfile(join(dirname(__file__), 'RsaLibrary', 'version.py'))


setup(
    name='robotframework-RsaLibrary',
    version=VERSION,
    author='Jules Barnes',
    author_email='jules@julesbarnes.com',
    packages=['RsaLibrary', 'RsaLibrary.test'],
    url='https://code.google.com/p/robotframework-RsaLibrary/',
    license='LICENSE.txt',
    description='Robot Framework Library allowing to encrypt and decrypt data',
    long_description=open('README.txt').read(),
    install_requires = ['pycrypto >= 2.6',
                        'robotframework-sshlibrary >= 1.1'],
)