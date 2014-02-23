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

import unittest, os, shutil
import RsaLibrary
from SSHLibrary import SSHLibrary

class TestKeyStoreLocation(unittest.TestCase):

    encryptionInstance = RsaLibrary.keywords()

    def setUp(self):
        # Creates a validTest Directory in users home directory
        self.validHomeDir = os.path.join(os.path.expanduser('~'), "validTest")
        self.invalidHomeDir = os.path.join(os.path.expanduser('~'), "invalidTest")
        self.validLocalDir = "validLocaTest"
        self.invalidLocalDir = "invalidLocalTest"
        
        os.mkdir(self.validHomeDir)
        os.mkdir(self.validLocalDir)


    def tearDown(self):
        os.rmdir(self.validHomeDir)
        os.rmdir(self.validLocalDir)

    def testValidHomeLocation(self):
        self.assertEqual(self.encryptionInstance.RSA_set_keystore_location(keyStoreFolder=self.validHomeDir), 
                         self.validHomeDir)

    def testValidLocalLocation(self):
        self.assertEqual(self.encryptionInstance.RSA_set_keystore_location(keyStoreFolder=self.validLocalDir, useHomeDir=False), 
                         self.validLocalDir)
                
    def testInvalidHomeLocation(self):
        with self.assertRaises(Exception) as context: 
            self.encryptionInstance.RSA_set_keystore_location(self.invalidHomeDir)
        self.assertEqual(context.exception.message,  "KeyStore does not exist: %s. Maybe you need to create some keys." % self.invalidHomeDir)

    def testInvalidLocalLocation(self):
        with self.assertRaises(Exception) as context: 
            self.encryptionInstance.RSA_set_keystore_location(self.invalidLocalDir, useHomeDir=False)
        self.assertEqual(context.exception.message,  "KeyStore does not exist: %s. Maybe you need to create some keys." % self.invalidLocalDir)

class TestKeyGeneration(unittest.TestCase):
    
    encryptionInstance = RsaLibrary.keywords()
    
    def setUp(self):
        # Creates a validTest Directory in users home directory
        self.keyStoreDir = os.path.join(os.path.expanduser('~'), "keyStoreTest")     
        self.testString = "This is a string that will be encrypted, signed, checked and dencrypted..."

    def tearDown(self):
        shutil.rmtree(self.keyStoreDir)
        pass
    
    def testKeyGeneration(self):
        self.encryptionInstance.RSA_generate_new_keys(self.keyStoreDir) # Creates new set of keys
        self.encryptionInstance.RSA_set_keystore_location(self.keyStoreDir)
        encryptedData = self.encryptionInstance.RSA_encrypt(self.testString) # Encrypts the string with the newly created keys
        encryptedDataSignature = self.encryptionInstance.RSA_sign_data(encryptedData) # Signs the encrypted string
        
        self.assertTrue(self.encryptionInstance.RSA_verify_signature(encryptedDataSignature, encryptedData))
        self.assertEqual(self.encryptionInstance.RSA_decrypt(encryptedData), self.testString)

class TestSSH(unittest.TestCase):

    encryptionInstance = RsaLibrary.keywords()
    sshSession = SSHLibrary()
    
    def setUp(self):
        self.keyStoreDir = os.path.join(os.path.expanduser('~'), "keyStoreSSHTest")
        self.encryptionInstance.RSA_generate_new_keys(self.keyStoreDir) # Creates new set of keys
        self.encryptionInstance.RSA_set_keystore_location(self.keyStoreDir)
        self.hostName = "192.168.126.147"
        self.hostUser = "tc"
        self.hostPass = "Password@01"
        
    def testSSHToServer(self):
        self.encryptionInstance.RSA_ssh_copy_key(self.hostName, self.hostUser, self.hostPass)
        keys = self.encryptionInstance.RSA_get_key_locations()
        self.sshSession.open_connection(self.hostName)
        self.sshSession.login_with_public_key(self.hostUser, keys["privateKey"], keys["privateKeyPass"])
        self.assertEqual(self.sshSession.execute_command("uname"), "Linux")
        
    def tearDown(self):
        shutil.rmtree(self.keyStoreDir)
           
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()