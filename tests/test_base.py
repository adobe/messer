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


import os
import types
import inspect
from messer import parse_args, get_default_config
from messer.abstracts import MesserAWSConfig, MesserAzureConfig
from messer.configure import AWSConfigure, AzureConfigure

CFG_FILE = "/".join([os.path.dirname(os.path.realpath(__file__)), 'tests.ini'])
# secret1 and secret2 will be uploaded during tests
DATA_BAG_ITEM_NAME = "secret1"
DATA_BAG_ITEM_FILE = "/".join([os.path.dirname(os.path.realpath(__file__)), 'resources', 'secret1.json'])
DATA_BAG_ITEM_NAME_2 = "secret2"
DATA_BAG_ITEM_FILE_2 = "/".join([os.path.dirname(os.path.realpath(__file__)), 'resources', 'secret2.json'])
# secret3 and secret4 are pre-uploaded and used to verify that access is restricted
DATA_BAG_ITEM_NAME_3 = "secret3"
DATA_BAG_ITEM_NAME_4 = "secret4"
DATA_BAG = "unittest"
SECRETS_FILE = 'adobe-messer-unittest'


def test_create_aws_config():
    """
    Ensures that specifying a new config file creates the file.
    :return:
    """
    args = parse_args(['configure', 'aws', '-c' 'new.ini', '-m' 'adobe-test', '-e' 'Dev', '-r' 'us-east-2', '-b' 'test-bucket'])
    cmd = AWSConfigure(args)
    cmd.execute()

    config = MesserAWSConfig(args.config)
    assert config.master_key == 'adobe-test'
    assert config.region == 'us-east-2'
    # make sure dev gets converted to lower case
    assert config.tier == 'dev'
    assert config.secrets_bucket == 'test-bucket'

    os.remove(config.filename)

def test_config():
    """
    Ensures that our configuration is set properly
    """
    config = MesserAWSConfig(open(CFG_FILE))

    assert config.keys_bucket == "adobe-envelope-keys-bucket-useast1"
    assert config.secrets_bucket == "adobe-secrets-bucket-useast1"
    assert config.master_key == "adobe-messer-unittest"
    assert config.role_arn == "arn:aws:iam::123456789101:role/adobe-messer-unittest"
    assert config.role_session_name == "messer_unittest"
    assert config.encryption_context == 'messer_unittest_context'


def test_parse_use_default_config():
    """
    Ensures that when no config is specified as an argument it attempts to use the file installed via pip
    """
    args = parse_args(['data', 'bag', 'create', 'aws', DATA_BAG])

    assert isinstance(args.config, types.FileType) is True
    assert args.config.name == get_default_config()


def test_parse_use_specified_config():
    """
    Ensures that the the -c argument correctly returns a file type
    """
    args = parse_args(['data', 'bag', 'create', 'aws', DATA_BAG, '-c', CFG_FILE, ])

    assert isinstance(args.config, types.FileType) is True
    assert args.config.name == CFG_FILE


def test_parse_create_data_bag():
    """
    Make sure that all of the options are available for creating data bags
    """
    args = parse_args(['data', 'bag', 'create', 'aws', DATA_BAG])

    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == "create_data_bag_aws"
    assert args.name == DATA_BAG


def test_parse_create_data_bag_item():
    """
    make sure that all of the options are available for creating encrypted data bag items
    """
    args = parse_args(['data', 'bag', 'from', 'file', 'aws', DATA_BAG, DATA_BAG_ITEM_FILE,
                       '--secret-file', SECRETS_FILE])

    assert isinstance(args.item, types.FileType)
    assert args.item.name == DATA_BAG_ITEM_FILE
    assert args.name == DATA_BAG
    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == 'upload_data_bag_aws'
    assert args.secret_file == SECRETS_FILE


def test_parse_show_data_bag_item():
    """
    make sure that all of the options are available for viewing encrypted data bag items
    """
    args = parse_args(['data', 'bag', 'show', 'aws', DATA_BAG, DATA_BAG_ITEM_NAME])

    assert args.item == DATA_BAG_ITEM_NAME
    assert args.name == DATA_BAG
    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == 'show_data_bag_aws'


def test_parse_delete_data_bag_item():
    """
    Make sure all the options are present for deleting a data bag items
    """
    args = parse_args(['data', 'bag', 'delete', 'aws', DATA_BAG, DATA_BAG_ITEM_NAME])

    assert args.item == DATA_BAG_ITEM_NAME
    assert args.name == DATA_BAG
    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == 'delete_data_bag_aws'


def test_parse_delete_data_bag():
    """
    Make sure all the options are present for deleting a data bags
    """
    args = parse_args(['data', 'bag', 'delete', 'aws', DATA_BAG])

    assert args.name == DATA_BAG
    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == 'delete_data_bag_aws'


def test_parse_encryption_create():
    """
    Make sure all the options are present for creating new cipher text keys
    """
    args = parse_args(['encryption', 'create', 'aws', 'adobe-messer-unittest'])

    assert args.key_name == 'adobe-messer-unittest'
    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == 'create_key_aws'


def test_parse_encryption_rotate():
    """
    Make sure all the options are present for rotating existing cipher text keys
    """
    args = parse_args(['encryption', 'increment', 'aws', 'adobe-messer-unittest'])

    assert args.key_name == 'adobe-messer-unittest'
    assert inspect.isfunction(args.command) is True
    assert args.command.__name__ == 'increment_key_version_aws'
