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

import boto
from boto.exception import S3ResponseError, JSONResponseError
import types
import test_base
import pytest
import json
from messer.databag import CreateAWSDataBag, ShowAWSDataBag, UploadAWSDataBag, DeleteAWSDataBag
from messer import parse_args

s3 = boto.connect_s3()

###### HELPER METHODS #####


def validate_common_props(cmd):
    assert cmd.sts is not None
    assert cmd.name == test_base.DATA_BAG
    assert cmd.secrets_bucket.name == "adobe-secrets-bucket-useast1"
    assert cmd.keys_bucket.name == "adobe-envelope-keys-bucket-useast1"


def compare_json(obj1, obj2):
    assert isinstance(obj1, dict)
    assert isinstance(obj2, dict)
    for key in obj1.keys():
        assert key in obj2
        assert obj1[key] == obj2[key]

def data_bag_exists(cmd, jsonfile):
    with open(jsonfile) as f:
        data = json.load(f)
        item_path = "{0}/{1}".format(cmd.path, data['id'])
        return cmd.exists(item_path)


####### SETUP / TEARDOWN ########


def teardown_function(function):
    """
    Delete both secret files as cleanup step
    """
    args = parse_args(['data', 'bag', 'delete', 'aws', test_base.DATA_BAG, test_base.DATA_BAG_ITEM_NAME, '-c', test_base.CFG_FILE])
    cmd = DeleteAWSDataBag(args)
    cmd.execute()

    args = parse_args(['data', 'bag', 'delete', 'aws', test_base.DATA_BAG, test_base.DATA_BAG_ITEM_NAME_2, '-c', test_base.CFG_FILE])
    cmd = DeleteAWSDataBag(args)
    cmd.execute()


####### TEST METHODS ########


def test_create_data_bag():
    """
    Ensures that messer can create data bags with folder names that match it's policy
    """
    args = parse_args(['data', 'bag', 'create', 'aws', test_base.DATA_BAG, '-c', test_base.CFG_FILE])
    cmd = CreateAWSDataBag(args)
    validate_common_props(cmd)
    cmd.execute()
    assert cmd.secrets_bucket.get_key(cmd.name + "/").name == test_base.DATA_BAG + "/"


def test_s3_policy_restricts_write():
    """
    Ensures that the unit test role does not have permission to write to folders which are not specifically defined.
    """
    args = parse_args(['data', 'bag', 'create', 'aws', "some-other-data-bag", '-c', test_base.CFG_FILE])
    cmd = CreateAWSDataBag(args)
    assert not cmd.name == test_base.DATA_BAG
    try:
        cmd.execute()
    except S3ResponseError, e:
        assert e.status == 403
        assert e.reason == "Forbidden"
        assert e.error_code == "AccessDenied"


def test_cannot_overwrite_existing_secrets():
    """
    Attempt to write over secret1, and verifies that it fails.
    """
    arglist = ['data', 'bag', 'from', 'file', 'aws', test_base.DATA_BAG, test_base.DATA_BAG_ITEM_FILE, '-c', test_base.CFG_FILE, '--secret-file', test_base.SECRETS_FILE]
    args = parse_args(arglist)
    cmd = UploadAWSDataBag(args)
    validate_common_props(cmd)
    if not data_bag_exists(cmd, test_base.DATA_BAG_ITEM_FILE):
        cmd.execute()
        cmd = UploadAWSDataBag(parse_args(arglist))
    assert isinstance(args.item, types.FileType)
    assert cmd.item.name == test_base.DATA_BAG_ITEM_FILE
    with pytest.raises(AttributeError):
        assert cmd.args.secrets_file is test_base.SECRETS_FILE
    with pytest.raises(RuntimeError):
        cmd.execute()


def test_can_overwrite_existing_secrets_with_force_flag():
    """
    Attempt to write over secret1 using the --force flag, and verifies that it succeeds.
    """
    args = parse_args(['data', 'bag', 'from', 'file', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_FILE, '-c', test_base.CFG_FILE,
                       '--force', '--secret-file', test_base.SECRETS_FILE])
    cmd = UploadAWSDataBag(args)
    assert not cmd.exists('secret2') is None
    validate_common_props(cmd)
    assert isinstance(args.item, types.FileType)
    assert cmd.item.name == test_base.DATA_BAG_ITEM_FILE
    with pytest.raises(AttributeError):
        assert cmd.args.secrets_file is test_base.SECRETS_FILE
    assert cmd.execute() > 0


def test_create_encrypted_item_from_file():
    """
    Ensures that secrets can be created from json files using the encryption keys provided to the role.
    """
    args = parse_args(['data', 'bag', 'from', 'file', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_FILE_2, '-c', test_base.CFG_FILE,
                       '--secret-file', test_base.SECRETS_FILE])
    cmd = UploadAWSDataBag(args)
    validate_common_props(cmd)
    assert isinstance(args.item, types.FileType)
    assert cmd.item.name == test_base.DATA_BAG_ITEM_FILE_2
    assert cmd.args.secret_file is test_base.SECRETS_FILE
    bytes_written = cmd.execute()
    assert bytes_written > 0
    # check that files exist in both buckets
    assert cmd.secrets_bucket.get_key(cmd.path + "/secret2").name == 'unittest/secret2'


def test_read_encrypted_data_bag_item():
    """
    Ensures that when the --decrypt flag is not passed the content is not decrypted.
    """
    # setup: upload secret
    args = parse_args(['data', 'bag', 'from', 'file', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_FILE_2, '-c', test_base.CFG_FILE,
                       '--secret-file', test_base.SECRETS_FILE])
    cmd = UploadAWSDataBag(args)
    validate_common_props(cmd)
    cmd.execute()

    # test: read secret
    args = parse_args(['data', 'bag', 'show', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_NAME_2, '-c', test_base.CFG_FILE])
    cmd = ShowAWSDataBag(args)
    validate_common_props(cmd)
    assert cmd.item == test_base.DATA_BAG_ITEM_NAME_2
    data_bag_item = cmd.execute()
    assert "encrypted_data" in data_bag_item
    assert "username" not in data_bag_item
    with open(test_base.DATA_BAG_ITEM_FILE_2) as data_file:
        orig_data = json.load(data_file)
    with pytest.raises(AssertionError):
        compare_json(orig_data, data_bag_item)


def test_read_and_decrypt_data_bag_item():
    """
    Ensures that when the --decrypt flag is passed we get the clear text.
    """
    # setup: upload secret
    args = parse_args(['data', 'bag', 'from', 'file', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_FILE_2, '-c', test_base.CFG_FILE,
                       '--secret-file', test_base.SECRETS_FILE])
    cmd = UploadAWSDataBag(args)
    validate_common_props(cmd)
    cmd.execute()

    # test: read secret
    args = parse_args(['data', 'bag', 'show', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_NAME_2, '-c', test_base.CFG_FILE,
                       '--decrypt'])
    cmd = ShowAWSDataBag(args)
    validate_common_props(cmd)
    assert cmd.item == test_base.DATA_BAG_ITEM_NAME_2
    data_bag_item = cmd.execute()
    assert "encrypted_data" not in data_bag_item
    assert "username" in data_bag_item
    with open(test_base.DATA_BAG_ITEM_FILE_2) as data_file:
        orig_data = json.load(data_file)
    # validate that orig_data is included in decrypted data_bag_item
    compare_json(orig_data, data_bag_item)


def test_read_non_existing_folder():
    """
    Listing the contents of 'some-none-existing-folder' on the secrets bucket returns no results (no exception)
    """
    args = parse_args(['data', 'bag', 'show', 'aws', "some-none-existing-folder", '-c', test_base.CFG_FILE, '--decrypt'])
    cmd = ShowAWSDataBag(args)
    assert not cmd.name == test_base.DATA_BAG
    cmd.execute()
    
    assert cmd.exists(cmd.path) is False


def test_role_s3_policy_restricts_read_existing_folder():
    """
    Ensures that the unit test role cannot list the contents of the 'dev' folder on the secrets bucket
    """
    args = parse_args(['data', 'bag', 'create', 'aws', "dev", '-c', test_base.CFG_FILE])
    cmd = CreateAWSDataBag(args)
    exception_thrown = None
    assert not cmd.name == test_base.DATA_BAG
    try:
        cmd.execute()
    except S3ResponseError, e:
        exception_thrown = True
        assert e.status == 403
        assert e.reason == "Forbidden"

    assert exception_thrown is True


def test_delete_data_bag_fails_if_not_empty():
    """
    Tests to make sure that messer cannot delete a data bag with items in it.
    """
    args = parse_args(['data', 'bag', 'delete', 'aws', test_base.DATA_BAG, '-c', test_base.CFG_FILE])
    cmd = DeleteAWSDataBag(args)
    assert cmd.name == test_base.DATA_BAG
    with pytest.raises(RuntimeError):
        cmd.execute()


def test_delete_data_bag_item():
    """
    Tests to make sure that messer can delete a secret
    """
    # setup: upload secret
    args = parse_args(['data', 'bag', 'from', 'file', 'aws',
                       test_base.DATA_BAG, test_base.DATA_BAG_ITEM_FILE, '-c', test_base.CFG_FILE,
                       '--secret-file', test_base.SECRETS_FILE])
    cmd = UploadAWSDataBag(args)
    validate_common_props(cmd)
    cmd.execute()

    # test to delete the data bag item
    args = parse_args(['data', 'bag', 'delete', 'aws',
                        test_base.DATA_BAG, test_base.DATA_BAG_ITEM_NAME, '-c', test_base.CFG_FILE])
    cmd = DeleteAWSDataBag(args)
    assert cmd.name == test_base.DATA_BAG
    assert cmd.item == 'secret1'
    assert cmd.execute() == 1
