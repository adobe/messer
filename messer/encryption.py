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


import argparse
import base64
import json
import messer
import os


from abstracts import S3Command, VaultCommand
from azure.keyvault.models.key_vault_error import KeyVaultErrorException
from azure.keyvault import KeyVaultId


# pycrypto is no longer maintained.  cryptography is now the preferred crypto lib and is used by other main stream
# apps such as paramiko and django.
# see https://cryptography.io/en/latest/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def add_common_cloud_provider_options(cloud_provider):
    cloud_provider.add_argument('key_name', help="The name of the encryption key.")
    cloud_provider.add_argument('-c', '--config',
                            default=messer.get_default_config(),
                            type=argparse.FileType('r'),
                            help="The configuration file to use.")

def options(subparser):
    """
    Defines the options for the 'messer encryption' commands. Arguments that call the set_defaults method, will call a
    function with the specified name and pass the parsed args to it. Anything that the method returns is assigned to
    the property 'command'.

    :param subparser: A sub parser object that these options can be added to.
    :type subparser: SubArgumentParser
    :return: None
    """
    encryption_parser = subparser.add_parser('encryption', help='Encryption Commands')
    encryption_parser = encryption_parser.add_subparsers(help="Encryption Sub Commands")

    create_parser = encryption_parser.add_parser('create', help="Create a new encryption key with the given name.")
    cloud_specific_encryption_create = create_parser.add_subparsers(help='Cloud Provider specific key creation.')

    rotate_parser = encryption_parser.add_parser('increment', help="Generate new version of specified encryption key.")
    cloud_specific_encryption_rotate = rotate_parser.add_subparsers(help='Cloud Provider specific key rotation.')

    list_parser = encryption_parser.add_parser('list', help="List the current encryption keys available.")
    cloud_specific_encryption_list = list_parser.add_subparsers(help='Cloud Provider specific key listing.')

    delete_parser = encryption_parser.add_parser('delete', help="Delete an encryption key or key version.")
    cloud_specific_encryption_delete = delete_parser.add_subparsers(help='Cloud Provider specific configuration.')

    # Encryption Services for AWS
    create_aws = cloud_specific_encryption_create.add_parser('aws', help='Create Encryption Key on AWS')
    create_aws.set_defaults(command=create_key_aws)
    add_common_cloud_provider_options(create_aws)

    rotate_aws = cloud_specific_encryption_rotate.add_parser('aws', help='Rotate Encryption Key on AWS')
    rotate_aws.set_defaults(command=increment_key_version_aws)
    add_common_cloud_provider_options(rotate_aws)

    list_aws = cloud_specific_encryption_list.add_parser('aws', help='List Encryption Keys on AWS')
    list_aws.set_defaults(command=list_keys_aws)
    list_aws.add_argument('key_name', help="The name of the encryption key.", nargs="?", default=None)
    list_aws.add_argument('-c', '--config',
                          default=messer.get_default_config(),
                          type=argparse.FileType('r'),
                          help="The configuration file to use.")

    delete_aws = cloud_specific_encryption_delete.add_parser('aws', help='Delete Encryption Key on AWS')
    delete_aws.set_defaults(command=delete_key_aws)
    add_common_cloud_provider_options(delete_aws)
    delete_aws.add_argument('key_version', nargs='?', help="The version of the key to delete.")
    delete_aws.add_argument('--no-prompt',
                            action='store_true',
                            help="Do not prompt user for confirmation. Just do it.")


    # Encryption Services for Azure
    create_azure = cloud_specific_encryption_create.add_parser('azure', help='Create Encryption Key on Azure')
    create_azure.set_defaults(command=create_key_azure)
    add_common_cloud_provider_options(create_azure)

    rotate_azure = cloud_specific_encryption_rotate.add_parser('azure', help='Rotate Encryption Key on Azure')
    rotate_azure.set_defaults(command=increment_key_version_azure)
    add_common_cloud_provider_options(rotate_azure)

    list_azure = cloud_specific_encryption_list.add_parser('azure', help='List Encryption Keys on Azure')
    list_azure.set_defaults(command=list_keys_azure)
    list_azure.add_argument('key_name', help="The name of the encryption key.", nargs="?", default=None)
    list_azure.add_argument('-c', '--config',
                            default=messer.get_default_config(),
                            type=argparse.FileType('r'),
                            help="The configuration file to use.")

    delete_azure = cloud_specific_encryption_delete.add_parser('azure', help='Delete Encryption Key on Azure')
    delete_azure.set_defaults(command=delete_key_azure)
    add_common_cloud_provider_options(delete_azure)
    delete_azure.add_argument('key_version', nargs='?', help="The version of the key to delete.")
    delete_azure.add_argument('--no-prompt',
                              action='store_true',
                              help="Do not prompt user for confirmation. Just do it.")


def get_latest_key_version(keys_bucket, key_name):
    key_versions = keys_bucket.list(prefix="{0}/".format(key_name))
    versions = []
    for key in key_versions:
        if not key.name.endswith("/"):
            version = key.name.split("/")[1]
            try:
                versions.append(int(version))
            except ValueError:
                raise RuntimeError("Unexpected non integer version found for {0}".format(key.name))
    versions.sort(reverse=True)
    return versions[0]




class EncryptionKey(object):
    """
    A class that represents and EncryptionKey object. Under the covers it decrypts the encrypted plain text key via the
    supplied key and then uses the plaintext key to create a new object capable of encrypting/un-encrypting
    AES-256 bit objects. The current encryption implementation is GCM as per Peleus's recommendation.

    The implementation largely follows a documented safe example from the GCM mode, but uses 256 bit instead
    of 96 bit as specified in the example. For more info visit review GCM mode at :
    https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#module-cryptography.hazmat.primitives.ciphers.modes
    """

    def __init__(self, data_key=None):
        """
        Initialize the object.
        """
        super(EncryptionKey, self).__init__()
        self._iv_length = 32

        if data_key:
            self._data_key = data_key

    def encrypt(self, key_name, to_encrypt, key_version, context=None):
        """
        Encrypts the the specified text using GCM

        :param to_encrypt: The text to encrypt
        :type to_encrypt: str

        :param context: The context that needs to be authenticated when decryption takes place.
        :type context: str

        :return: base64 encoded str
        """
        iv = os.urandom(self._iv_length)
        encryptor = Cipher(algorithms.AES(self._data_key), modes.GCM(iv), backend=default_backend()).encryptor()

        if context:
            encryptor.authenticate_additional_data(context)

        # super important that finalize is called, don't trust the encryption until AFTER finalize has been called.
        encrypted_secret = encryptor.update(to_encrypt) + encryptor.finalize()
        jsonstr = json.dumps({"iv": base64.b64encode(iv),
                              "encrypted_secret": base64.b64encode(encrypted_secret),
                              "tag": base64.b64encode(encryptor.tag),
                              "key_name": key_name,
                              "key_version": key_version,
                              "version": "1"})  # change this for any drastic changes to how encryption works.
        return base64.b64encode(jsonstr)

    def decrypt(self, to_decrypt, context=None):
        """
        un-encrypt the specified text. Text should be base64 encoded.

        :param to_decrypt: The base64 encoded text to decrypt.
        :type to_decrypt: str

        :param context: The context that was used when encrypting the content (needed for authentication)
        :type context: str

        :return: str
        """
        encrypted = json.loads(base64.b64decode(to_decrypt))
        iv = base64.b64decode(encrypted['iv'])
        encrypted_secret = base64.b64decode(encrypted['encrypted_secret'])
        tag = base64.b64decode(encrypted['tag'])

        decryptor = Cipher(algorithms.AES(self._data_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

        if context:
            decryptor.authenticate_additional_data(context)

        return decryptor.update(encrypted_secret) + decryptor.finalize()


class AzureEncryptionKeyLoader(object):
    """Azure Specific EncryptionKey Loader class"""

    def __init__(self):
        super(AzureEncryptionKeyLoader, self).__init__()

    def decrypt_key(self, encrypted_key, vault_conn, key_vault_uri, master_key_name, key_version, master_key_algorithm):
        """
        gets the plain text key
        :return: str
        """

        # base64 decode key to get encrypted key
        encrypted_key = base64.decodestring(encrypted_key)

        # use vault RSA master key to un-encrypt and get a AES256 key
        decrypted_key = vault_conn.decrypt(key_vault_uri, master_key_name, key_version, master_key_algorithm,
                                           encrypted_key).result

        return base64.decodestring(decrypted_key)

    @staticmethod
    def load(name, key_version, az_vault_client, az_vault_base_url, master_key_algorithm):

        """
        Creates a new EncryptionKey object after downloading the encryption key from the given vault and decrypting it
        using the mentioned master key.

        :param name: The name of the encryption key
        :type name: str

        :param key_version: The version of the encryption key to use. Default is the latest
        :type key_version: Azure Key version object

        :param az_vault_client: A connection to Azure Vault.
        :type az_vault_client: VaultConnection

        :param az_vault_base_url: URL for the Azure Vault. Ex: https://myvault.vault.azure.net.
        :type az_vault_base_url: str

        :param master_key_algorithm: Master Key Algorithm
        :type master_key_algorithm: str

        :return: EncryptionKey
        """

        try:
            encrypted_data_secret = az_vault_client.get_secret(az_vault_base_url, name, key_version)
            encrypted_key = encrypted_data_secret.value

            master_key_name = encrypted_data_secret.tags.get('master_key')
            master_key_version = encrypted_data_secret.tags.get('master_key_version')
            if not master_key_name or not master_key_version:
                raise RuntimeError("Cannot find the master key for {}".format(name))

            decrypted_data_key = AzureEncryptionKeyLoader.decrypt_key(AzureEncryptionKeyLoader(), encrypted_key,
                                                                      az_vault_client, az_vault_base_url,
                                                                      master_key_name, master_key_version,
                                                                      master_key_algorithm)

            return EncryptionKey(data_key=decrypted_data_key)

        except KeyVaultErrorException:
            raise RuntimeError("Could not find the encryption key {} in vault {}".format(name, az_vault_base_url))


class AWSEncryptionKeyLoader(object):
    """AWS Specific EncryptionKey class"""

    def __init__(self):
        super(AWSEncryptionKeyLoader, self).__init__()

    def decrypt_key(self, kms_conn, encrypted_key):
        """
        Gets the plain text key from AWS KMS.

        :param kms_conn: Connection to AWS KMS.
        :type kms_conn: KMSConnection

        :param encrypted_key: Encrypted Data Key
        :type encrypted_key: str

        :return: str
        """

        return kms_conn.decrypt(encrypted_key).get('Plaintext')

    @staticmethod
    def load(name, bucket, kms_conn, key_version):
        """
        Creates a new EncryptionKey object for the mentioned Data Key.

        :param name: The name of the encryption key
        :type name: str

        :param bucket: An S3 Bucket object
        :type bucket: Bucket

        :param kms_conn: A connection to KMS.
        :type kms_conn: KMSConnection

        :param key_version: The version of the encryption key to use
        :type key_version: int

        :return: EncryptionKey
        """

        key_version = int(key_version)

        path = "{0}/{1}".format(name, key_version)

        if bucket.get_key(path):
            encrypted_data_key = bucket.get_key(path).get_contents_as_string()
            decrypted_data_key = AWSEncryptionKeyLoader.decrypt_key(AWSEncryptionKeyLoader(), kms_conn,
                                                                    encrypted_data_key)

            # Return EncryptionKey object.
            return EncryptionKey(decrypted_data_key)

        else:
            raise RuntimeError("Could not find the encryption key {}".format(path))


class CreateAWSEncryptionKey(S3Command):
    """
    A messer command that will create a new MasterKey.
    KMS MasterKey and encrypted key object are created and uploaded it to S3.
    """

    def __init__(self, args):
        super(CreateAWSEncryptionKey, self).__init__(args)

    @property
    def key_name(self):
        """
        The name of the key to use.

        :return: str
        """
        return self.args.key_name

    def get_master_key(self, alias):
        """
        Fetches a KMS master key by an alias and returns the id if found.

        :param alias: The alias to a master key
        :type alias: str

        :return: str
        """
        response = self.kms.describe_key(alias)
        return response['KeyMetadata']["KeyId"]

    def create_encrypted_key(self, key_id):
        """
        Creates a new encrypted encryption key using KMS.  Note that the plain text version of this key can only be
        obtained by decrypting it using KMS master key that was used to create it.  If you lose this key, you will
        not be able to decrypt any secrets or credentials that you have encrypted with it - so keep it safe!

        :param key_id: The KMS master key to use for encryption.
        :type key_id: str

        :return: str
        """
        data_key = self.kms.generate_data_key_without_plaintext(key_id, key_spec='AES_256')
        return data_key.get('CiphertextBlob')

    def save(self, encrypted_key, version):
        """
        Saves the new KMS encrypted encrypted key to s3 using the specified version
        :param encrypted_key: The newly generated KMS encryption key
        :type encrypted_key: str
        :param version: The version of the key
        :type version: int
        :return: The bytes written
        :raises: RuntimeError if the specified key and version already exist
        """
        if not self.keys_bucket.get_key("{0}/{1}".format(self.key_name, version)):
            folder = self.new_folder(self.key_name, self.keys_bucket)
            bytes_written = self.add_file(folder, str(version), encrypted_key, self.keys_bucket)
            if not self.config.silent:
                print("Encryption key {0} version {1} created!".format(self.key_name, version))
            return bytes_written
        else:
            print "A key with this name already exists. If you need to increment your key, please use 'increment' cmd"
            raise RuntimeError("Encryption Key Version Exists")

    def execute(self):
        """
        Performs the following tasks:
          1. Get a Master Key object
          2. Generate a new encrypted encryption key using the newly created master key
          3. Upload the new encrypted key to the configured S3 bucket or vault
          4. Returns an 'EncryptionKey' object which can be used to encrypting and decrypting strings using GCM.

        :return: EncryptionKey
        """
        alias = "alias/{0}".format(self.config.master_key)

        # get the master key id and get a encryption key from it.
        key_id = self.get_master_key(alias)
        encrypted_key = self.create_encrypted_key(key_id)

        # save the key to s3 bucket.
        version = 0
        self.save(encrypted_key, version)

        # return an EncryptionKey object to the caller.
        return EncryptionKey()

class CreateAzureEncryptionKey(VaultCommand):
    """
    A messer command that will create a new MasterKey.
    Generate an Azure Vault Key.
    """

    @property
    def key_name(self):
        """
        The _name of the key to use.

        :return: str
        """
        return self.args.key_name

    def __init__(self, args):
        super(CreateAzureEncryptionKey, self).__init__(args)

    def get_latest_master_key_version(self):
        master = self.vault.get_key(self.config.key_vault_uri, self.config.master_key, self.default_azure_key_version)
        return master.key.kid.split("/")[-1:][0]

    def save(self, encrypted_key):
        # save the resulting blob in azure vault as a secret with mentioned metadata tags.
        tags = {'content-nature': 'encryption-key', 'master_key': self.config.master_key,
                'master_key_version': self.get_latest_master_key_version(),
                'local_encryption_algorithm': self.secret_encryption_algorithm, 'key-length': '256 bits',
                'is_base64_encoded': True}
        secret = self.vault.set_secret(self.config.key_vault_uri, self.key_name, encrypted_key, tags)
        version = self.get_item_version(secret)
        if not self.config.silent:
            print("Encryption key {0} version {1} created!".format(self.key_name, version))
        return version

    def generate_key(self):
        # generate a encryption key in plain text locally and base64 encode it
        plain_text_key = os.urandom(self.aes_key_length)
        base64_encoded_pt_key = base64.encodestring(plain_text_key)

        # encrypt the encoded key using a master RSA private key in vault and encode the resulting blob.
        encrypted_key = self.vault.encrypt(self.config.key_vault_uri, self.config.master_key,
                                           self.default_azure_key_version, self.azure_key_encryption_algorithm,
                                           base64_encoded_pt_key).result
        encrypted_key = base64.encodestring(encrypted_key)
        return encrypted_key

    def check_key_exists(self):
        try:
            self.vault.get_secret(self.config.key_vault_uri, self.key_name, self.default_azure_key_version)
            return True
        except KeyVaultErrorException:
            return False

    def execute(self):
        if self.check_key_exists():
            raise RuntimeError("A key with the same name exists.")
        self.save(self.generate_key())
        return EncryptionKey()


class IncrementAWSKeyVersion(CreateAWSEncryptionKey):
    """
    A messer command that will generate a new envelop encryption key, and save it under the next incremental version.
    I.e If the current version of the key 'test' was '0' then this command would create a new key and store it at
    version '1'.
    """

    def __init__(self, args):
        super(IncrementAWSKeyVersion, self).__init__(args)

    def execute(self):
        """
        Performs the following tasks:
          1. Get a KMS Master Key object
          2. Generate a new encrypted encryption key using the specified KMS master key
          3. Upload the new encrypted key to the configured S3 bucket under the current version number + 1
          4. Returns an 'EncryptionKey' object which can be used to encrypting and decrypting strings using GCM.

        :return: EncryptionKey
        """

        alias = "alias/{0}".format(self.config.master_key)
        key_id = self.get_master_key(alias)
        version = get_latest_key_version(self.keys_bucket, self.key_name) + 1
        encrypted_key = self.create_encrypted_key(key_id)
        self.save(encrypted_key, version)

        return version


class IncrementAzureKeyVersion(CreateAzureEncryptionKey):
    """
    A messer command that will generate a new envelop encryption key for use in Azure, and save it under a new version.
    The Azure API differs from AWS, and overwriting a secret automatically results in a new version which is returned
    from the API.
    """

    def __init__(self, args):
        super(IncrementAzureKeyVersion, self).__init__(args)

    def execute(self):
        if self.check_key_exists():
            return self.save(self.generate_key())
        else:
            raise RuntimeError("No key with that name exists.  Create one first!")


class ListAWSEncryptionKeys(S3Command):
    """
    Lists all the encryption keys and versions
    """

    def __init__(self, args):
        super(ListAWSEncryptionKeys, self).__init__(args=args)

    def execute(self):
        """
        Depending on parameters Lists all of the encryption keys and versions, or only the specific versions of a key
        """
        output = []
        if self.args.key_name:
            for entry in self.keys_bucket.list(prefix=self.args.key_name + "/"):
                if not entry.name.endswith("/"):
                    version = entry.name.split('/')[1]
                    if not self.config.silent:
                        print(version)
                    output.append(version)
        else:
            for entry in self.keys_bucket.list():
                if entry.name.endswith('/'):
                    if not self.config.silent:
                        print entry.name[:-1]
                    output.append(entry.name)

        return output


class ListAzureEncryptionKeys(VaultCommand):
    """
    Lists all the encryption keys and versions
    """

    def __init__(self, args):
        super(ListAzureEncryptionKeys, self).__init__(args=args)

    def execute(self):
        """
        Depending on parameters Lists all of the encryption keys and versions, or only the specific versions of a key
        """
        output = []
        # list out all of the versions for the specified key
        if self.args.key_name:
            vault_items = self.vault.get_secret_versions(self.config.key_vault_uri, self.args.key_name)
            for item in vault_items:
                key_id = self.get_item_version(item)
                if not self.config.silent:
                    print(key_id)
                output.append(key_id)
        # list all vault items and look for the vault item with tag 'encryption-key'
        else:
            vault_items = self.vault.get_secrets(self.config.key_vault_uri)
            for vault_item in vault_items:
                if vault_item.tags and vault_item.tags.get('content-nature') == 'encryption-key':
                    if not self.config.silent:
                        print(vault_item.id.split('/')[-1])
                    output.append(vault_item.id.split('/')[-1])

        return output


class DeleteAWSEncryptionKey(S3Command):
    """
    Delete an EncryptionKey or only a specific version from S3.
    """

    def __init__(self, args):
        super(DeleteAWSEncryptionKey, self).__init__(args=args)

    def delete(self, key, version):
        path = "{0}/{1}".format(key, version)
        if not self.config.silent:
            print("Deleting Encryption Key: {0}".format(path))
        key = self.keys_bucket.get_key(path)
        if key:
            key.delete()
        else:
            print("Key {0} was not found".format(path))

    def delete_key_and_versions(self):
        for entry in self.keys_bucket.list(prefix=self.args.key_name):
            key = self.keys_bucket.get_key(entry.name)
            if key:
                if not self.config.silent:
                    print("Deleting Encryption Key: {}".format(key.name))
                key.delete()

    def execute(self):
        """
        Attempts to delete a specific version of version of the data key.
        :return: True if the encryption key was deleted, otherwise,  False.
        """
        if self.args.key_name and self.args.key_version:
            if self.args.no_prompt:
                self.delete(self.args.key_name, self.args.key_version)
            else:
                i = raw_input("You are about to delete the following:\nKey: {0}\nVer: {1}\n\nAre you sure? [N/y]: "
                              .format(self.args.key_name, self.args.key_version)) or 'n'
                if i.lower() == 'n':
                    print("No action taken.")
                    return False
                elif i.lower() == 'y':
                    self.delete(self.args.key_name, self.args.key_version)
                else:
                    raise RuntimeError("Key Name and Key Version are required parameters.")
            return True

        elif self.args.key_name and not self.args.key_version:
            if self.args.no_prompt:
                self.delete_key_and_versions()
            else:
                i = raw_input("You are about to delete {0} and all its versions.\nAre you sure? [N/y]: "
                              .format(self.args.key_name)) or 'n'
                if i.lower() == 'n':
                    print("No action taken.")
                    return False
                elif i.lower() == 'y':
                    self.delete_key_and_versions()
                else:
                    raise RuntimeError("Invalid Input.  Valid choices are 'n' or 'y'")


class DeleteAzureEncryptionKey(VaultCommand):
    """
    Deletes an encryption key on an Azure vault
    """

    def __init__(self, args):
        super(DeleteAzureEncryptionKey, self).__init__(args=args)

    def execute(self):
        """
        Attempts to delete a specific version of version of the data key.
        :return: True if the encryption key was deleted, otherwise,  False.
        """

        if not self.args.key_name:
            raise RuntimeError("Key Name is a required parameter.")
        else:
            # list all vault items and look for the vault item with tag 'encryption-key'
            vault_item = self.vault.get_secret(self.config.key_vault_uri, self.args.key_name,
                                               self.default_azure_key_version)

            if vault_item.tags and vault_item.tags.get('content-nature') == 'encryption-key':
                self.vault.delete_secret(self.config.key_vault_uri, self.args.key_name)
                return

            raise RuntimeError("The said key was not found {}".format(self.args.key_name))


# method will be invoked automatically during argument parsing.
def create_key_aws(args):
    return CreateAWSEncryptionKey(args)


# method will be invoked automatically during argument parsing.
def create_key_azure(args):
    return CreateAzureEncryptionKey(args)


# method will rotate keys
def increment_key_version_aws(args):
    return IncrementAWSKeyVersion(args)


# method will rotate keys
def increment_key_version_azure(args):
    return IncrementAzureKeyVersion(args)


# method will delete key
def delete_key_aws(args):
    return DeleteAWSEncryptionKey(args)


# method will delete key
def delete_key_azure(args):
    return DeleteAzureEncryptionKey(args)


# method will list keys
def list_keys_aws(args):
    return ListAWSEncryptionKeys(args)


# method will list keys
def list_keys_azure(args):
    return ListAzureEncryptionKeys(args)
