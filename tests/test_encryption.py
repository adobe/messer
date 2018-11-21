"""

(c) 2018 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.

"""


__author__ = 'Jed Glazner, Sandeep Srivastav Vaddiparthy, Florian Noeding, Heiko Hahn'

import pytest
import test_base
from boto.exception import S3ResponseError
from messer.encryption import *
from messer import parse_args

TEST_KEY_ID = "<insert the key id of the kms key id fetched from the aws kms console>"
PLAIN_TEXT = "The british are coming!"
SUCCESS_CONTEXT = "Paul Revere"
VERSION_0 = 0
VERSION_1 = 1


def setup_encryptor():
    # use this key to fetch the encryption object.
    args = parse_args(['encryption', 'create', 'aws', 'adobe-messer-unittest', '-c', test_base.CFG_FILE])
    cmd = CreateAWSEncryptionKey(args)
    encrypter = AWSEncryptionKeyLoader.load(cmd.args.key_name, cmd.keys_bucket, cmd.kms, VERSION_0)

    return dict(encryptor=encrypter, name=cmd.args.key_name,
                key_version=get_latest_key_version(cmd.keys_bucket, cmd.args.key_name))


def test_get_or_create_key():
    """
    Ensures that getting the master key by alias returns the proper id.
    """
    args = parse_args(['encryption', 'create', 'aws', 'adobe-messer-unittest', '-c', test_base.CFG_FILE])
    cmd = CreateAWSEncryptionKey(args)
    assert cmd.get_master_key('alias/adobe-messer-unittest') == TEST_KEY_ID


def test_new_key_version():
    """
    Ensures that key rotation generates an incremental version
    """
    args = parse_args(['encryption', 'create', 'aws', 'adobe-messer-unittest-rotation', '-c', test_base.CFG_FILE])
    create_cmd = CreateAWSEncryptionKey(args)
    create_cmd.execute()
    assert get_latest_key_version(create_cmd.keys_bucket, create_cmd.args.key_name) == VERSION_0

    # increment the key version of the newly created key and get the latest version which should be 1.
    args = parse_args(['encryption', 'increment', 'aws', 'adobe-messer-unittest-rotation', '-c', test_base.CFG_FILE])
    cmd = IncrementAWSKeyVersion(args)
    cmd.execute()
    assert get_latest_key_version(cmd.keys_bucket, cmd.args.key_name) == VERSION_1

    # delete version 1 of this key
    del_cmd = DeleteAWSEncryptionKey(parse_args(['encryption', 'delete', 'aws', 'adobe-messer-unittest-rotation', '1',
                                                '--no-prompt', '-c', test_base.CFG_FILE]))
    del_cmd.execute()
    assert get_latest_key_version(cmd.keys_bucket, cmd.args.key_name) == VERSION_0

    # delete base key to have a fresh version of the key and then create the said key
    del_cmd = DeleteAWSEncryptionKey(parse_args(['encryption', 'delete', 'aws', 'adobe-messer-unittest-rotation',
                                                 '--no-prompt', '-c', test_base.CFG_FILE]))
    del_cmd.execute()


def test_create_envelope_key_fails_on_duplicate():
    """
    Ensures that we can create only one key with the same name and version.
    """
    args = parse_args(['encryption', 'create', 'aws', 'adobe-messer-unittest', '-c', test_base.CFG_FILE])
    cmd = CreateAWSEncryptionKey(args)
    exception_thrown = False
    try:
        cmd.execute()
    except RuntimeError, e:
        exception_thrown = True

    assert exception_thrown is True


def test_encryption_success():
    """
    Ensures that our encryption algorithm is working as expected.
    """
    encryptor = setup_encryptor()
    encrypted_secret = encryptor['encryptor'].encrypt(encryptor['name'], PLAIN_TEXT, encryptor['key_version'],
                                                 SUCCESS_CONTEXT)
    assert encryptor['encryptor'].decrypt(encrypted_secret, SUCCESS_CONTEXT) == PLAIN_TEXT


def test_fail_context():
    """
    Ensures that when the wrong context is passed, the decryption fails.
    """
    encryptor = setup_encryptor()
    encrypted_secret = encryptor['encryptor'].encrypt(encryptor['name'], PLAIN_TEXT, encryptor['key_version'],
                                                      SUCCESS_CONTEXT)
    with pytest.raises(Exception):
        encryptor['encryptor'].decrypt(encrypted_secret, "George Washington")


def test_fail_wrong_key():
    """
    Ensures that you cannot decrypt a secret from the wrong key
    """
    encryptor = setup_encryptor()
    cipher_text = encryptor['encryptor'].encrypt(encryptor['name'], PLAIN_TEXT, encryptor['key_version'],
                                                 SUCCESS_CONTEXT)

    # generate a new key, and try to decrypt the contents from the previous key.
    encryptor2 = setup_encryptor()['encryptor']
    with pytest.raises(Exception):
        encryptor2.decrypt(cipher_text, "Paul is not Revered") == PLAIN_TEXT


def test_role_restricts_kms_key_creation_s3():
    """
    Access to the cipher text key 'adobe-common' in S3 is NOT allowed by the unit test policy
    """
    args = parse_args(['encryption', 'create', 'aws', 'adobe-common', '-c', test_base.CFG_FILE ])
    cmd = CreateAWSEncryptionKey(args)
    exception_thrown = False
    try:
        cmd.execute()
    except S3ResponseError, e:
        exception_thrown = True
        assert e.status == 403
        assert e.reason == "Forbidden"

    assert exception_thrown is True
