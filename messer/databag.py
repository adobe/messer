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


import messer
import argparse
import json
from messer.abstracts import S3Command, VaultCommand
from messer.encryption import AWSEncryptionKeyLoader, AzureEncryptionKeyLoader, get_latest_key_version
from azure.keyvault.models.key_vault_error import KeyVaultErrorException


def create_options(data_bag_parser):
    """
    Adds the 'data bag create' command along with it's options.
    :param data_bag_parser: The 'data bag' parser
    :return: None
    """
    create = data_bag_parser.add_parser('create', help="Create a new directory in S3 to store the data bag for AWS. "
                                                       "Do nothing for Azure.")
    cloud_specific_create = create.add_subparsers(help='Cloud Provider specific configuration.')

    # AWS specific configuration options.
    create_in_aws = cloud_specific_create.add_parser('aws', help='DataBag creation in AWS')
    create_in_aws.set_defaults(command=create_data_bag_aws)

    create_in_aws.add_argument('name', help="The name of the data bag")
    create_in_aws.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                               help="The configuration file to use.")

    # Azure specific configuration options.
    create_in_azure = cloud_specific_create.add_parser('azure', help='DataBag creation in Azure')
    create_in_azure.set_defaults(command=create_data_bag_azure)

    create_in_azure.add_argument('name', help="The name of the data bag")
    create_in_azure.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                                 help="The configuration file to use.")


def from_file_options(data_bag_parser):
    """
    Adds the 'data bag from file' command along with it's options.
    :param data_bag_parser: The 'data bag' parser
    :return: None
    """
    from_parser = data_bag_parser.add_parser('from', help="from the {file} to the destination {name}")
    from_subparser = from_parser.add_subparsers(help="From File Parser")
    from_file = from_subparser.add_parser('file', help="From File")

    cloud_specific_upload = from_file.add_subparsers(help='Cloud Provider specific configuration.')

    # Upload DataBags to Azure
    from_file_azure = cloud_specific_upload.add_parser('azure', help='DataBag upload in Azure')
    from_file_azure.set_defaults(command=upload_data_bag_azure)

    from_file_azure.add_argument('name', help="The name of the data bag")
    from_file_azure.add_argument('item', type=argparse.FileType('r'), help="DataBag to upload (should be json format)")
    from_file_azure.add_argument('--force', action='store_true', help="Force overwrite the existing data bag item")
    from_file_azure.add_argument('--secret-file', required=True,
                                 help="The name of the encryption key to use when encrypting the secret")
    from_file_azure.add_argument('-v', '--key-version', default='latest', help="Version of the encryption key to use.")
    from_file_azure.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                                 help="The configuration file to use.")

    # Upload DataBags to AWS
    from_file_aws = cloud_specific_upload.add_parser('aws', help='DataBag upload in AWS')
    from_file_aws.set_defaults(command=upload_data_bag_aws)

    from_file_aws.add_argument('name', help="The name of the data bag")
    from_file_aws.add_argument('item', type=argparse.FileType('r'), help="DataBag to upload (should be json format)")
    from_file_aws.add_argument('--force', action='store_true', help="Force overwrite the existing data bag item")
    from_file_aws.add_argument('--secret-file', required=True, help="The name of the encryption key to use when encrypting the secret")
    from_file_aws.add_argument('-v', '--key-version', default='latest', help="Version of the encryption key to use.")
    from_file_aws.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                               help="The configuration file to use.")


def show_options(data_bag_parser):
    """
    Adds the 'data bag show' command along with it's options.
    :param data_bag_parser: The 'data bag' parser
    :return: None
    """
    show = data_bag_parser.add_parser('show', help="List the items or databags")
    cloud_specific_show = show.add_subparsers(help='Cloud Provider specific configuration.')

    # Azure specific show
    show_in_azure = cloud_specific_show.add_parser('azure', help='DataBag creation in Azure')
    show_in_azure.set_defaults(command=show_data_bag_azure)

    show_in_azure.add_argument('name', nargs='?', help="The name of the data bag")
    show_in_azure.add_argument('item', help="The data bag item to show", nargs='?')
    show_in_azure.add_argument('--decrypt', action='store_true',
                               help="Decrypt the secret. Default is to use the embedded key_name and key_version.")
    show_in_azure.add_argument('--secret-file',
                               help="The version of the encryption key to use. "
                                    "Note till version 1.2.0 this is not necessary as the name of the key & version are"
                                    "embedded in the secret itself.Specifying this parameter however,on secrets created"
                                    "before 1.2.0 will still require this parameter. "
                                    "In versions > 1.2.0 it will override the embedded key_version in the secret.")
    show_in_azure.add_argument('--key-version',
                               help="The version of the encryption key to use. "
                                    "Note till version 1.2.0 this is not necessary as the name of the key & version are"
                                    "embedded in the secret itself.Specifying this parameter however,on secrets created"
                                    "before 1.2.0 will still require this parameter. "
                                    "In versions > 1.2.0 it will override the embedded key_version in the secret.")
    show_in_azure.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                               help="The configuration file to use.")

    # AWS specific show
    show_in_aws = cloud_specific_show.add_parser('aws', help='DataBag show in AWS')
    show_in_aws.set_defaults(command=show_data_bag_aws)

    show_in_aws.add_argument('name', nargs='?', help="The name of the data bag")
    show_in_aws.add_argument('item', help="The data bag item to show", nargs='?')
    show_in_aws.add_argument('--decrypt', action='store_true',
                             help="Decrypt the secret. Default is to use the embedded key_name and key_version.")
    show_in_aws.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                             help="The configuration file to use.")


def delete_options(data_bag_parser):
    """
    Adds the 'data bag delete' command along with it's options.
    :param data_bag_parser: The 'data bag' parser
    :return: None
    """
    delete = data_bag_parser.add_parser('delete', help="Delete a date bag item")
    cloud_specific_delete = delete.add_subparsers(help='Cloud Provider specific configuration.')

    # Azure specific delete
    delete_in_azure = cloud_specific_delete.add_parser('azure', help='DataBag deletion in Azure')
    delete_in_azure.set_defaults(command=delete_data_bag_azure)

    delete_in_azure.add_argument('name', help="The name of the data bag")
    delete_in_azure.add_argument('item', nargs='?', help="The data bag item to delete")
    delete_in_azure.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                                 help="The configuration file to use.")

    # AWS specific delete
    delete_in_aws = cloud_specific_delete.add_parser('aws', help='DataBag deletion in AWS')
    delete_in_aws.set_defaults(command=delete_data_bag_aws)

    delete_in_aws.add_argument('name', help="The name of the data bag")
    delete_in_aws.add_argument('item', nargs='?', help="The data bag item to delete")
    delete_in_aws.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('r'),
                               help="The configuration file to use.")

def options(subparser):
    """
    Defines argument options for data bag commands. Arguments that call the set_defaults method, will call a function
    with the specified name and pass the parsed args to it. Anything that the method returns is assigned to the property
    'command'.

    :param subparser: A sub parser object that these options can be added to.
    :type subparser: SubArgumentParser
    :return: None
    """
    # data bag item
    data = subparser.add_parser('data', help='Data Commands')
    data_parser = data.add_subparsers(help="Data Sub Commands")

    bag = data_parser.add_parser('bag', help="Data Bag Command")
    data_bag_parser = bag.add_subparsers(help="Data Bag sub Commands")

    create_options(data_bag_parser)
    from_file_options(data_bag_parser)
    show_options(data_bag_parser)
    delete_options(data_bag_parser)


class AWSDataBag(S3Command):
    """
    Base class for all DataBag commands.
    """

    def __init__(self, args):
        super(AWSDataBag, self).__init__(args=args)

    @property
    def name(self):
        """
        The value of the 'name' positional argument.
        """
        return self.args.name

    @property
    def path(self):
        """
        The path within the bucket which is made of up the tier, and folder from the configuration file.
        """
        paths = []
        if self.config.tier:
            paths.append(self.config.tier)
        if self.config.secrets_folder:
            paths.append(self.config.secrets_folder)
        if self.name:
            paths.append(self.name)

        return "/".join(paths)

    def exists(self, path):
        if self.secrets_bucket.get_key(path) is None:
            return False
        return True

    def execute(self):
        pass


class AzureDataBag(VaultCommand):
    """
    Base class for all DataBag commands.
    """

    def __init__(self, args):
        super(AzureDataBag, self).__init__(args=args)

    @property
    def name(self):
        """
        The value of the 'name' positional argument.
        """
        return self.args.name

    def execute(self):
        pass


class CreateAWSDataBag(AWSDataBag):
    """
    Class the contains the logic needed to create a new 'data bag'. Technically this doesn't need to even exist,
    but since messer is trying as much as possible to copy knife commands it exists because in chef,
    you cannot create a data bag item with out first creating a data bag.

    This creates a folder in the specified S3 bucket.
    """

    def __init__(self, args):
        super(CreateAWSDataBag, self).__init__(args=args)

    def execute(self):
        """
        Creates an empty 'folder' in S3 for the data bag.
        """

        if self.secrets_bucket_name:
            if not self.config.silent:
                print("Creating new data bag: {0} ({1}) in {2}".format(self.name, self.path, self.secrets_bucket_name))
            self.new_folder(self.path, self.secrets_bucket)
        else:
            raise RuntimeError("'None' is not a valid bucket name.")


class CreateAzureDataBag(AzureDataBag):
    """
    Class the contains the logic needed to create a new 'data bag'. Technically this doesn't need to even exist,
    but since messer is trying as much as possible to copy knife commands it exists because in chef,
    you cannot create a data bag item with out first creating a data bag.

    In Azure databag name is nothing but a prefix to the item name. Does nothing
    """

    def __init__(self, args):
        super(CreateAzureDataBag, self).__init__(args=args)

    def execute(self):
        """
        Creates an empty 'folder' in S3 for the data bag.
        """
        return "In Azure databag name is nothing but a prefix to the item name. Directly create a data bag item."


class DataBag(object):
    def __init__(self, args, config):
        super(DataBag, self).__init__()

    def encrypt_item(self, data_bag_item, encryption_key, key_version, key_name, encryption_context=None):
        """
        Encrypts the given data bag item.  This also slightly different from chef as messer will just encrypt the
        the entire dictionary as a single item, where as chef will encrypt only the 'values' of the individual
        dictionary items.  However, given that you must use messer to un-encrypt items encrypted with messer, this saves
        code and complexity.

        :param data_bag_item: A dictionary containing the data that needs to be encrypted.
        :type data_bag_item: dict

        :param encryption_key: The key to be used for encryption.
        :type encryption_key: Encryption Key Object

        :param key_name: Name of the key to be used for encryption.
        :type key_name: str

        :param key_version: key version
        :type key_version: str

        :param encryption_context: AWS specific encryption context
        :type encryption_context: Encryption Context or None

        :return: dict
        """
        plaintext = json.dumps(data_bag_item)

        encrypted = encryption_key.encrypt(key_name, plaintext, key_version, encryption_context)

        return {'id': data_bag_item['id'],
                'encrypted_data': encrypted,
                'key_name': key_name,
                'key_version': key_version}


class UploadAWSDataBag(AWSDataBag, DataBag):
    """
    A messer command that creates a new 'data bag item' from a file and uploads it. The functionality
    replaces chefs 'knife data bag from file' command. The file to be read needs to adhere to chef data bag format.

    Uploads a file to S3.
    """

    def __init__(self, args):
        super(UploadAWSDataBag, self).__init__(args=args)

    @property
    def item(self):
        """
        The name of the data bag item to be used.
        :return: str
        """
        return self.args.item

    def upload(self, data_bag_item):
        """
        Verifies and uploads the specified data bag item to S3 encrypting it first if specified.
        :param data_bag_item: a dict containing an id field at the top level.
        :return: the number of bytes written to S3
        :raises: RunTimeError for validation or API failures.
        """
        self.validate(data_bag_item)

        if self.args.key_version == 'latest':
            key_version = get_latest_key_version(self.keys_bucket, self.args.secret_file)
        else:
            key_version = self.args.key_version
        encryption_key = AWSEncryptionKeyLoader.load(self.args.secret_file, self.keys_bucket, self.kms, key_version)
        encrypted_item = self.encrypt_item(data_bag_item=data_bag_item, encryption_key=encryption_key,
                                           key_version=key_version, key_name=self.args.secret_file)

        item_key = self.secrets_bucket.new_key("{0}/{1}".format(self.path, data_bag_item['id']))
        bytes_written = item_key.set_contents_from_string(json.dumps(encrypted_item))
        if not self.config.silent:
            print("Created new data bag item {0}/{1} with key {2} in {3}"
                    .format(self.name, data_bag_item['id'], self.args.secret_file, self.secrets_bucket_name))

        return bytes_written

    def validate(self, data_bag_item):
        """
        Checks the following:
        1. Verifies that the data bag item is a dictionary
        2. Ensures the dict has an 'id' element at the top
        3. That the specified 'data bag' or 'folder' that will be used to put the item into exists.
        4. That the data bag *item* doesn't already exist.

        :param data_bag_item: A dict containing at least an id field.
        """
        if not isinstance(data_bag_item, dict) or 'id' not in data_bag_item:
            raise RuntimeError("The data bag item must be json & must contain an 'id' element.")

        if not self.exists(self.path + '/'):
            raise RuntimeError("The data bag {0} ({1}/) does not exist. Please create it first!".format(self.name, self.path))

        item_path = "{0}/{1}".format(self.path, data_bag_item['id'])
        if not self.args.force and self.exists(item_path):
            raise RuntimeError("Item {0} already exists in the {1} data bag!".format(data_bag_item['id'], self.name))

    def execute(self):
        """
        Reads and converts JSON file from disk into a data bag item and uploads it to S3.
        If the --secret-file argument was passed the newly created data bag item will also will also encrypted using
        the name of the DataKey specified in the --secret-file argument.
        :return: The number of bytes written during the operation.
        """
        data_bag_item = json.load(self.item)
        return self.upload(data_bag_item)


class UploadAzureDataBag(AzureDataBag, DataBag):
    """
    A messer command that creates a new 'data bag item' from a file and uploads it. The functionality
    replaces chefs 'knife data bag from file' command. The file to be read needs to adhere to chef data bag format.

    In Azure databag name is nothing but a prefix to the item name. Directly create a data bag item.
    """

    def __init__(self, args):
        super(UploadAzureDataBag, self).__init__(args=args)

    @property
    def item(self):
        """
        The name of the data bag item to be used.
        :return: str
        """
        return self.args.item

    def check_key_exists(self, item):
        try:
            self.vault.get_secret(self.config.key_vault_uri, self.item_name(item), self.default_azure_key_version)
            return True
        except KeyVaultErrorException:
            return False

    def item_name(self, item):
        return '--'.join([self.name, item['id']])

    def validate(self, item):
        """
        Validates that `item` is a dictionary, and that it contains an id field, and that it doesn't already exist.
        """
        if not isinstance(item, dict) or not 'id' in item:
            raise RuntimeError("The data bag item must be json & must contain an 'id' element.")
        if self.check_key_exists(item) and not self.args.force:
            raise RuntimeError("Item {0} already exists!".format(self.item_name(item)))

        return True

    def get_key_version(self):
        if self.args.key_version == 'latest':
            kek = self.vault.get_secret(self.config.key_vault_uri, self.args.secret_file, self.default_azure_key_version)
            return self.get_item_version(kek)
        return self.args.key_version

    def execute(self):
        """
        Reads and converts JSON file from disk into a dictionary, encrypts it, adds metadata and and uploads it Azure.
        """
        data_bag_item = json.load(self.item)
        self.validate(data_bag_item)
        key_version = self.get_key_version()

        encryption_key = AzureEncryptionKeyLoader.load(name=self.args.secret_file,
                                                       key_version=key_version,
                                                       az_vault_client=self.vault,
                                                       az_vault_base_url=self.config.key_vault_uri,
                                                       master_key_algorithm=self.azure_key_encryption_algorithm)

        data_bag_item = self.encrypt_item(data_bag_item=data_bag_item, encryption_key=encryption_key,
                                          key_version=key_version, key_name=self.args.secret_file)

        # save the resulting blob in azure vault as a secret with mentioned metadata tags.
        tags = {'content-nature': 'databag-item', 'encryption_key': self.args.secret_file,
                'local_encryption_algorithm': key_version,
                'is_base64_encoded': True}
        return self.vault.set_secret(self.config.key_vault_uri, self.item_name(data_bag_item), json.dumps(data_bag_item), tags=tags)


class ShowAWSDataBag(AWSDataBag):
    def __init__(self, args):
        super(ShowAWSDataBag, self).__init__(args=args)

    @property
    def item(self):
        """
        The name of the data bag item to show.
        :return: str
        """
        return self._args.item

    def show_item(self):
        """
        Retrieves a data bag item from S3/Vault optionally decrypting it before displaying it.
        :return: json
        """

        def show_encrypted():
            encrypted = data_bag_item.pop('encrypted_data')
            decrypted = key.decrypt(encrypted)
            data_bag_item.update(json.loads(decrypted))

        secret = self.secrets_bucket.get_key("{0}/{1}".format(self.path, self.item))

        if not secret:
            raise RuntimeError("Unable to find {0} in data bag {1}".format(self.item, self.name))

        data_bag_item = json.loads(secret.get_contents_as_string())
        if self.args.decrypt:
            if "key_name" in data_bag_item and "key_version" in data_bag_item:
                #TODO: Remove this hack after all databags have been re-encrypted.
                #SEE: https://jira.corp.adobe.com/browse/SCLD2-17946
                if data_bag_item['key_version'] == 'latest':
                    data_bag_item['key_version'] = 0
                key = AWSEncryptionKeyLoader.load(data_bag_item['key_name'], self.keys_bucket, self.kms, data_bag_item['key_version'])
                show_encrypted()
            else:
                raise RuntimeError("Unable to decrypt the secret because no encryption key was specified.")
        else:
            if not self.config.silent:
                print(json.dumps(data_bag_item))
            return data_bag_item

        if not self.config.silent:
            print(json.dumps(data_bag_item))
        return data_bag_item

    def show_data_bag(self):
        """
        List the data bag item names for the given data bag
        :return: list of data bag names
        """
        elements = []
        if self.exists(self.path + "/"):
            elements = []
            if not self.config.silent:
                print("items in data bag: {0}".format(self.name))
            for item in self.secrets_bucket.list(prefix=self.path + "/"):
                if not item.name.endswith("/"):
                    # print out the name of the items with out the prefix
                    item_name = item.name.replace(self.path + "/", "")
                    if not self.config.silent:
                        print(item_name)
                    elements.append(item_name)

        else:
            if not self.config.silent:
                print("No data bag named: {0} ({1}/)".format(self.name, self.path))

        return elements

    def list_data_bags(self):
        """
        List the data bags.
        :return: list of data bag names
        """
        data_bags = []
        path = self.path + "/"
        if path == "/":
            path = ""
        for item in self.secrets_bucket.list(prefix=path):
            name = item.name
            if name.endswith("/") and name.startswith(self.path) and name[:-1] != self.path:
                data_bag = name[:-1].split("/")[-1]

                if not self.config.silent:
                    print(data_bag)
                data_bags.append(data_bag)

        return data_bags

    def execute(self):
        """
        Downloads the  'data bag item' from S3/Vault and prints it out.
        If the data bag was encrypted and the --secret-file argument was passed,
        then it will print out the decrypted contents.
        :return: None
        """
        if self.name and self.item:
            return self.show_item()
        elif self.name:
            return self.show_data_bag()
        else:
            return self.list_data_bags()


class ShowAzureDataBag(AzureDataBag):
    def __init__(self, args):
        super(ShowAzureDataBag, self).__init__(args=args)

    @property
    def item(self):
        """
        The name of the data bag item to show.
        :return: str
        """
        return self._args.item

    def decrypt_and_print(self, data_bag_item):
        key = AzureEncryptionKeyLoader.load(data_bag_item['key_name'],
                                            key_version=data_bag_item['key_version'],
                                            az_vault_client=self.vault, az_vault_base_url=self.config.key_vault_uri,
                                            master_key_algorithm=self.azure_key_encryption_algorithm)
        encrypted = data_bag_item.pop('encrypted_data')
        decrypted = key.decrypt(encrypted)
        data_bag_item.update(json.loads(decrypted))
        if not self.config.silent:
            print(json.dumps(data_bag_item))
        return data_bag_item

    def show_item(self):
        """
        Retrieves a data bag item from Vault optionally decrypting it before displaying it.
        :return: json
        """
        data_bag_item_name = '--'.join([self.name, self.item])
        raw = self.vault.get_secret(self.config.key_vault_uri, data_bag_item_name, self.default_azure_key_version).value
        data_bag_item = json.loads(raw)

        if self.args.decrypt:
            return self.decrypt_and_print(data_bag_item)
        else:
            if not self.config.silent:
                print(json.dumps(data_bag_item))
        return data_bag_item

    def show_data_bag(self):
        """
        List the data bag item names for the given data bag
        :return: list of data bag names
        """
        elements = []
        secrets = self.vault.get_secrets(self.config.key_vault_uri)
        for secret in secrets:
            secret_name = secret.id.split('/')[-1]
            if secret_name.startswith(self.name):
                if not self.config.silent:
                    print(secret_name)
                elements.append(secret_name)

        return elements

    def list_data_bags(self):
        """
        List the data bags.
        :return: list of data bag names
        """

        secrets = self.vault.get_secrets(self.config.key_vault_uri)
        data_bags = set()
        for secret in secrets:
            secret_name = secret.id.split('/')[-1]
            data_bags.add('-'.join(secret_name.split('--')[:-1]))

        data_bags = list(data_bags)
        for data_bag in data_bags:
            if not self.config.silent:
                print(data_bag)

        return data_bags

    def execute(self):
        """
        Downloads the  'data bag item' from S3/Vault and prints it out.
        If the data bag was encrypted and the --secret-file argument was passed,
        then it will print out the decrypted contents.
        :return: None
        """
        if self.name and self.item:
            return self.show_item()
        elif self.name:
            return self.show_data_bag()
        else:
            return self.list_data_bags()


class DeleteAWSDataBag(AWSDataBag):
    """
    Deletes a data bag item from S3.
    """

    def __init__(self, args):
        super(DeleteAWSDataBag, self).__init__(args=args)

    @property
    def item(self):
        """
        The name of the data bag item to delete.
        :return:
        """
        return self._args.item

    @property
    def name(self):
        """
        The name of the data bag to delete.
        :return:
        """
        return self._args.name

    def execute(self):
        """
        Attempts to delete a data bag or data bag item from the configured S3 bucket.  If the positional argument 'item'
        is not present, then it will attempt to delete the data bag.  The data bag can only be deleted however, if it
        has no more items in side.
        :return: 1
        """
        if self.name and self.item:
            self.secrets_bucket.delete_key("{0}/{1}".format(self.path, self.item))
            return 1
        else:
            contents = []
            for item in self.secrets_bucket.list(prefix=self.path + '/'):
                if not item.name.endswith("/"):
                    contents.append(item.name.replace(self.path, ""))
            if len(contents) < 1:
                self.secrets_bucket.delete_key(self.name + '/')
                return 1
            else:
                if not self.config.silent:
                    print("The data bag is not empty! Please delete the following items and try again:")
                    for entry in contents:
                        print(entry.replace("/", ""))
                raise RuntimeError("The data bag is not empty!")


class DeleteAzureDataBag(AzureDataBag):
    """
    Deletes a data bag item from Vault.
    """

    def __init__(self, args):
        super(DeleteAzureDataBag, self).__init__(args=args)

    @property
    def item(self):
        """
        The name of the data bag item to delete.
        :return:
        """
        return self._args.item

    @property
    def name(self):
        """
        The name of the data bag to delete.
        :return:
        """
        return self._args.name

    def execute(self):
        """
        Attempts to delete a data bag or data bag item .

        It can only delete an databag item. Azure does not have databags. They are just item name prefixes

        :return: None
        """
        if self.name and self.item:
            vault_secret_name = '-'.join([self.name, self.item])
            self.vault.delete_secret(self.config.key_vault_uri, vault_secret_name)
        else:
            to_delete = []
            secrets = self.vault.get_secrets(self.config.key_vault_uri)
            for secret in secrets:
                secret_name = secret.id.split('/')[-1]
                if secret_name.startswith(self.name) and secret.tags.get('content-nature') == 'databag-item':
                    to_delete.append(secret_name)

            for secret in to_delete:
                self.vault.delete_secret(self.config.key_vault_uri, secret)


# method will be invoked automatically during argument parsing.
def create_data_bag_aws(args):
    return CreateAWSDataBag(args)


def create_data_bag_azure(args):
    return CreateAzureDataBag(args)


# method will be invoked automatically during argument parsing.
def upload_data_bag_aws(args):
    return UploadAWSDataBag(args)


# method will be invoked automatically during argument parsing.
def upload_data_bag_azure(args):
    return UploadAzureDataBag(args)


# method will be invoked automatically during argument parsing.
def show_data_bag_aws(args):
    return ShowAWSDataBag(args)


# method will be invoked automatically during argument parsing.
def show_data_bag_azure(args):
    return ShowAzureDataBag(args)


# method will be invoked automatically during argument parsing.
def delete_data_bag_azure(args):
    return DeleteAzureDataBag(args)


def delete_data_bag_aws(args):
    return DeleteAWSDataBag(args)
