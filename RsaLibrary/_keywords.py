'''
Copyright 03/01/2014 Jules Barnes

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from SSHLibrary import SSHLibrary


class keywords(object):

    def __init__(self,
                publicKeyName="myPublicKey.pem",
                privateKeyName="myPrivateKey.pem",
                privateKeyPass="passphrase",
                opensshKeyName="myOpenssh.key"):

        self.publicKeyName = publicKeyName
        self.privateKeyName = privateKeyName
        self.opensshKeyName = opensshKeyName
        self.privateKeyPass = privateKeyPass

    def RSA_set_keystore_location(self,
                             keyStoreFolder="keyStore",
                             useHomeDir=True):

        if useHomeDir == True:
            # key store location
            self.keyStore = os.path.join(os.path.expanduser('~'),
                                         keyStoreFolder)
        else:
            # key store location
            self.keyStore = keyStoreFolder

        # Tests for key store existence
        if not os.path.exists(self.keyStore):
            raise Exception("KeyStore does not exist: %s. \
                             Maybe you need to create some keys."
                            % self.keyStore)

        return self.keyStore

    def RSA_get_key_locations(self):

        keyLocations = {}
        keyLocations['publicKey'] = os.path.join(self.keyStore,
                                                 self.publicKeyName)
        keyLocations['privateKey'] = os.path.join(self.keyStore,
                                                  self.privateKeyName)
        keyLocations['privateKeyPass'] = self.privateKeyPass
        keyLocations['opensshKey'] = os.path.join(self.keyStore,
                                                  self.opensshKeyName)

        return keyLocations

    def RSA_generate_new_keys(self, outputFolder, bits=2048):
        new_key = RSA.generate(bits)

        if os.path.exists(outputFolder):
            raise Exception("Output folder %s already exists!!"
                             % outputFolder)
        else:
            os.mkdir(outputFolder)

        self._save_key_file(os.path.join(outputFolder, self.publicKeyName),
                            new_key.publickey().exportKey("PEM"))

        self._save_key_file(os.path.join(outputFolder, self.opensshKeyName),
                            new_key.publickey().exportKey("OpenSSH"))

        self._save_key_file(os.path.join(outputFolder, self.privateKeyName),
                            new_key.exportKey("PEM", self.privateKeyPass))

    def RSA_encrypt(self, data):
        key = self._read_file(os.path.join(self.keyStore, self.publicKeyName))
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(str(data))
        return encrypted.encode('base64')

    def RSA_decrypt(self, data):
        key = self._read_file(os.path.join(self.keyStore, self.privateKeyName))
        rsakey = RSA.importKey(key, self.privateKeyPass)
        rsakey = PKCS1_OAEP.new(rsakey)
        decrypted = rsakey.decrypt(b64decode(data))
        return decrypted

    def RSA_sign_data(self, data):
        global keyStore
        key = self._read_file(os.path.join(self.keyStore, self.privateKeyName))
        rsakey = RSA.importKey(key, self.privateKeyPass)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        digest.update(b64decode(data))
        sign = signer.sign(digest)
        return b64encode(sign)

    def RSA_verify_signature(self, signature, data):
        key = self._read_file(os.path.join(self.keyStore, self.publicKeyName))
        rsakey = RSA.importKey(key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        digest.update(b64decode(data))
        if signer.verify(digest, b64decode(signature)):
            return True
        return False

    def RSA_ssh_copy_key(self, host, username, password):
        """
        Login With Public Key(username,
                              keyLocations['privateKey'],
                              'passphrase')
        """
        sshLibSession = SSHLibrary(loglevel='WARN')
        fo = open(os.path.join(self.keyStore, self.opensshKeyName), "rb")
        sshKey = fo.read()
        fo.close()
        sshLibSession.open_connection(host)
        sshLibSession.login(username, password)
        sshLibSession.execute_command("mkdir .ssh")
        sshLibSession.execute_command((("echo %s > .ssh/authorized_keys")
                                       % (sshKey)))
        sshLibSession.execute_command("chmod 700 .ssh")
        sshLibSession.execute_command("chmod 600 .ssh/authorized_keys")
        sshLibSession.close_connection()

    def _save_key_file(self, myKeyFileName, myKeyFile):
        f = open(myKeyFileName, 'w')
        f.write(myKeyFile)
        f.close()

    def _read_file(self, fileName):
        try:
            fo = open(fileName, "rb")
        except IOError:
            raise Exception(("Unable to open %s") % (fileName))

        fileContents = fo.read()
        fo.close()
        return fileContents
