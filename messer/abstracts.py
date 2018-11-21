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
from boto import kms
import ConfigParser
import os

from abc import ABCMeta, abstractmethod
from azure.keyvault import KeyVaultClient, KeyVaultId
from azure.common.credentials import ServicePrincipalCredentials


class MesserCommand(object):
    """
    Abstract class for all messer commands.
    """

    @property
    def args(self):
        """
        Gets the args that were parsed by the argument parser.
        :return: Namespace
        """
        return self._args

    @property
    def config(self):
        """
        The messer configuration object.
        :return: MesserConfig
        """
        return self._cfg

    def __init__(self, args, config=None):
        self._args = args
        self._cfg = config

    @abstractmethod
    def execute(self):
        pass


class MesserAWSCommand(MesserCommand):
    """
    Abstract class for all messer commands on AWS.
    """

    def __init__(self, args, init_conn=True):
        super(MesserAWSCommand, self).__init__(args, config=MesserAWSConfig(args.config))

        # set up STS if needed
        if init_conn:
            self.sts = None
            if self.config.role_arn:
                if self.config.aws_profile:
                    self.sts_conn = boto.connect_sts(profile_name=self.config.aws_profile)
                else:
                    self.sts_conn = boto.connect_sts()
                response = self.sts_conn.assume_role(self.config.role_arn, self.config.role_session_name)
                self.sts = response.credentials.to_dict()
            # get S3 & KMS connections
            self._connect_kms()
            self._connect_s3()

    def _connect_kms(self):
        """
        Attempts to get a KMSConnection first from sts. If sts is not configured, then it will obtain a connection using
        the configured profile (if profile is not configured default is used)
        """
        boto.connect_kms()
        if self.sts:
            self.kms = kms.connect_to_region(self.config.region,
                                             aws_access_key_id=self.sts["access_key"],
                                             aws_secret_access_key=self.sts["secret_key"],
                                             security_token=self.sts["session_token"])

        elif self.config.aws_profile:
            self.kms = kms.connect_to_region(self.config.region, profile_name=self.config.aws_profile)
        else:
            self.kms = kms.connect_to_region(self.config.region)

    def _connect_s3(self):
        """
        Attempts to get a S3Connection first from sts. If sts is not configured, then it will obtain a connection using
        the configured profile (if profile is not configured default is used)
        """
        if self.sts:
            self.s3 = boto.connect_s3(aws_access_key_id=self.sts["access_key"],
                                      aws_secret_access_key=self.sts["secret_key"],
                                      security_token=self.sts["session_token"])
        elif self.config.aws_profile:
            self.s3 = boto.connect_s3(profile_name=self.config.aws_profile)
        else:
            self.s3 = boto.connect_s3()


class MesserAzureCommand(MesserCommand):
    """
    Abstract class for all messer commands on Azure.
    """

    def __init__(self, args, init_conn=True):
        super(MesserAzureCommand, self).__init__(args, config=MesserAzureConfig(args.config))

        if init_conn:
            # get Vault connection
            self._connect_azure_vault()

            # set some cryptographic constants.
            self.azure_key_encryption_algorithm = 'RSA-OAEP-256'
            self.secret_encryption_algorithm = 'aes256'
            # 256 bits or 8 bytes
            self.aes_key_length = 32

    def _connect_azure_vault(self):
        """Attempts to get a Azure KeyVault connection using the credentials specified in the messer config"""
        credentials = ServicePrincipalCredentials(
            client_id=self.config.azure_client_id,
            secret=os.environ['AZURE_CLIENT_SECRET'],
            subscription=self.config.azure_subscription_id,
            tenant=self.config.azure_tenant_id
        )

        self.vault = KeyVaultClient(credentials)
        self.default_azure_key_version = KeyVaultId.version_none

class VaultCommand(MesserAzureCommand):
    """
    Base MesserCommand for all Vault related commands.
    """
    __metaclass__ = ABCMeta

    def __init__(self, args):
        super(VaultCommand, self).__init__(args)
        self.config.verify()

    def get_item_version(self, item):
        return item.id.split("/")[-1:][0]


class KMSCommand(MesserAWSCommand):
    """
    Base MesserCommand for all KMS related commands.
    """
    __metaclass__ = ABCMeta

    def __init__(self, args):
        super(KMSCommand, self).__init__(args)
        self.config.verify()


class S3Command(MesserAWSCommand):
    """
    Base MesserCommand for all S3 objects.
    """
    __metaclass__ = ABCMeta

    def __init__(self, args):
        super(S3Command, self).__init__(args)
        self.config.verify()

    @property
    def secrets_bucket(self):
        """
        The Bucket where the actual secrets/credentials will be kept.
        """
        return self.s3.get_bucket(self.secrets_bucket_name)

    @property
    def secrets_bucket_name(self):
        """
        The name of the bucket where secrets/credentials will be kept.
        """
        return self.config.secrets_bucket

    @property
    def keys_bucket(self):
        """
        The Bucket where the encryption keys will be kept.
        """
        return self.s3.get_bucket(self.keys_bucket_name)

    @property
    def keys_bucket_name(self):
        """
        The _name of the bucket where the encryption keys will be kept.
        """
        return self.config.keys_bucket

    @staticmethod
    def new_folder(name, bucket):
        """
        Creates a new 'folder' with the given name, in the bucket that was passed. If the 'folder' already exists,
        return it.

        :param name: The _name of the folder. If `name` contains a '/', all the folders in the path are created.
        :type name: str
        :param bucket: The S3 Bucket object to create the folder on.
        :type bucket: Bucket
        """
        if not name.endswith("/"):
            name += "/"
        # if the folder already exists, just return it.
        folder = bucket.get_key(name)
        if folder:
            return folder

        progress = ""
        for part in name.split("/"):
            progress += part + "/"
            if not bucket.get_key(progress):
                key = bucket.new_key(progress)
                key.set_contents_from_string('')
                key.set_canned_acl('private')

        return bucket.get_key(name)

    @staticmethod
    def add_file(folder, filename, contents, bucket):
        """
        Adds a file to S3 using the `filename` parameter as the name and the `contents` parameter as the value.

        :param folder: A Key object that is returned from the boto.s3.Bucket.new_key() method
        :type folder: boto.gs.key.Key
        :param filename: The name of of the file to put into the folder
        :type filename: str
        :param contents: The contents to put into t
        :type contents: str
        :param bucket: The bucket where the file should be uploaded to.
        :type bucket: Bucket
        """
        if bucket.get_key(folder.name):
            path = "{0}/{1}".format(folder.name, filename)
            key = bucket.new_key(path)
            return key.set_contents_from_string(contents)


class MesserConfig(object):
    """
    Configuration class for messer.
    """
    # These break down the configuration ini
    MESSER_SECTION = 'messer'
    MASTER_KEY = 'master_key'
    REGION = 'region'
    TIER = 'tier'
    SILENT = 'silent'

    def __init__(self, cfg_file):
        if cfg_file:
            self.filename = cfg_file.name
            self._cfg = ConfigParser.ConfigParser()
            self._cfg.read(cfg_file.name)
        else:
            raise RuntimeError("No file specified for MesserConfig")

    @property
    def master_key(self):
        try:
            return self._cfg.get(self.MESSER_SECTION, self.MASTER_KEY)
        except ConfigParser.NoOptionError as e:
            return None

    @master_key.setter
    def master_key(self, master_key):
        self._cfg.set(self.MESSER_SECTION, self.MASTER_KEY, master_key)


    @property
    def tier(self):
        try:
            return self._cfg.get(self.MESSER_SECTION, self.TIER)
        except ConfigParser.NoOptionError as e:
            return None

    @tier.setter
    def tier(self, tier):
        tier = tier.lower()
        self._cfg.set(self.MESSER_SECTION, self.TIER, tier)

    @property
    def silent(self):
        try:
            return self._cfg.getboolean(self.MESSER_SECTION, self.SILENT)
        except ConfigParser.NoOptionError as e:
            return False

    @silent.setter
    def silent(self, silent):
        if type(silent) is not bool:
            raise RuntimeError("Silent must be a boolean!")
        self._cfg.set(self.MESSER_SECTION, self.SILENT, silent)

    @property
    def common_required_configurations(self):
        return ['master_key']

    def pre_process(self, required_sections):
        required_sections.append('messer')
        for section in required_sections:
            if not self._cfg.has_section(section):
                self._cfg.add_section(section)

        for section in self._cfg.sections():
            if section not in required_sections:
                self._cfg.remove_section(section)

    def save(self):
        with open(self.filename, 'w') as configfile:
            self._cfg.write(configfile)

    def display(self):
        print("Config File: {0}".format(self.filename))
        for section in self._cfg.sections():
            print("[{}]".format(section))
            for key, value in self._cfg.items(section):
                print("\t{0}={1}".format(key, value))


class MesserAWSConfig(MesserConfig):
    """
    Configuration class for messer on AWS.
    """

    # AWS related config
    MESSER_AWS_SECTION = 'aws'
    SECRETS_BUCKET = 'secrets_bucket'
    KEYS_BUCKET = 'keys_bucket'
    ROLE_ARN = 'role_arn'
    ROLE_SESSION_NAME = 'role_session_name'
    AWS_PROFILE = 'aws_profile'
    ENCRYPTION_CONTEXT = 'encryption_context'
    SECRETS_FOLDER = 'secrets_folder'

    def __init__(self, cfg_file):
        super(MesserAWSConfig, self).__init__(cfg_file)

    # aws related config in the messer.ini
    @property
    def secrets_bucket(self):
        # This is required so it's ok to raise an exception if it's not present.
        return self._cfg.get(self.MESSER_AWS_SECTION, self.SECRETS_BUCKET)

    @secrets_bucket.setter
    def secrets_bucket(self, bucket_name):
        self._cfg.set(self.MESSER_AWS_SECTION, self.SECRETS_BUCKET, bucket_name)

    @property
    def keys_bucket(self):
        # This is required so it's ok to raise an exception if it's not present.
        return self._cfg.get(self.MESSER_AWS_SECTION, self.KEYS_BUCKET)

    @keys_bucket.setter
    def keys_bucket(self, bucket_name):
        self._cfg.set(self.MESSER_AWS_SECTION, self.KEYS_BUCKET, bucket_name)

    @property
    def aws_profile(self):
        try:
            return self._cfg.get(self.MESSER_AWS_SECTION, self.AWS_PROFILE)
        except ConfigParser.NoOptionError:
            return None

    @aws_profile.setter
    def aws_profile(self, aws_profile):
        self._cfg.set(self.MESSER_AWS_SECTION, self.AWS_PROFILE, aws_profile)

    @property
    def role_arn(self):
        try:
            return self._cfg.get(self.MESSER_AWS_SECTION, self.ROLE_ARN)
        except ConfigParser.NoOptionError:
            return None

    @role_arn.setter
    def role_arn(self, role_arn):
        self._cfg.set(self.MESSER_AWS_SECTION, self.ROLE_ARN, role_arn)

    @property
    def role_session_name(self):
        try:
            return self._cfg.get(self.MESSER_AWS_SECTION, self.ROLE_SESSION_NAME)
        except ConfigParser.NoOptionError as e:
            return None

    @role_session_name.setter
    def role_session_name(self, role_session_name):
        self._cfg.set(self.MESSER_AWS_SECTION, self.ROLE_SESSION_NAME, role_session_name)

    @property
    def encryption_context(self):
        try:
            return self._cfg.get(self.MESSER_AWS_SECTION, self.ENCRYPTION_CONTEXT)
        except ConfigParser.NoOptionError as e:
            return None

    @encryption_context.setter
    def encryption_context(self, encryption_context):
        self._cfg.set(self.MESSER_AWS_SECTION, self.ENCRYPTION_CONTEXT, encryption_context)

    @property
    def region(self):
        try:
            return self._cfg.get(self.MESSER_AWS_SECTION, self.REGION)
        except ConfigParser.NoOptionError as e:
            return None

    @region.setter
    def region(self, region):
        self._cfg.set(self.MESSER_AWS_SECTION, self.REGION, region)

    @property
    def secrets_folder(self):
        try:
            return self._cfg.get(self.MESSER_AWS_SECTION, self.SECRETS_FOLDER)
        except ConfigParser.NoOptionError as e:
            return None

    @secrets_folder.setter
    def secrets_folder(self, folder):
        self._cfg.set(self.MESSER_AWS_SECTION, self.SECRETS_FOLDER, folder)

    def verify(self):
        # defining a list of config variables that are required to be set.
        aws_required_configurations = ['secrets_bucket', 'keys_bucket', 'master_key', 'role_arn', 'region']

        required_params = dict(common=self.common_required_configurations, aws=aws_required_configurations)

        def verify_param():
            if not getattr(self, param, None):
                raise RuntimeError("Config element '{0}' is not configured! Please edit your config file: {1}"
                                   .format(getattr(self, param.upper()), self.filename))

        # verifying required configuration parameters
        for section in required_params:
            for param in required_params[section]:
                verify_param()


class MesserAzureConfig(MesserConfig):
    """
    Configuration class for messer on Azure.
    """
    # Azure related config
    MESSER_AZURE_SECTION = 'azure'
    AZURE_CLIENT_ID = 'azure_client_id'
    AZURE_SUBSCRIPTION_ID = 'azure_subscription_id'
    AZURE_TENANT_ID = 'azure_tenant_id'
    KEY_VAULT_URI = 'azure_key_vault_uri'

    def __init__(self, cfg_file):
        super(MesserAzureConfig, self).__init__(cfg_file)

    @property
    def azure_client_id(self):
        return self._cfg.get(self.MESSER_AZURE_SECTION, self.AZURE_CLIENT_ID)

    @azure_client_id.setter
    def azure_client_id(self, azure_client_id):
        self._cfg.set(self.MESSER_AZURE_SECTION, self.AZURE_CLIENT_ID, azure_client_id)

    @property
    def azure_subscription_id(self):
        return self._cfg.get(self.MESSER_AZURE_SECTION, self.AZURE_SUBSCRIPTION_ID)

    @azure_subscription_id.setter
    def azure_subscription_id(self, azure_subscription_id):
        self._cfg.set(self.MESSER_AZURE_SECTION, self.AZURE_SUBSCRIPTION_ID, azure_subscription_id)

    @property
    def azure_tenant_id(self):
        return self._cfg.get(self.MESSER_AZURE_SECTION, self.AZURE_TENANT_ID)

    @azure_tenant_id.setter
    def azure_tenant_id(self, azure_tenant_id):
        self._cfg.set(self.MESSER_AZURE_SECTION, self.AZURE_TENANT_ID, azure_tenant_id)

    @property
    def key_vault_uri(self):
        return self._cfg.get(self.MESSER_AZURE_SECTION, self.KEY_VAULT_URI)

    @key_vault_uri.setter
    def key_vault_uri(self, key_vault_uri):
        self._cfg.set(self.MESSER_AZURE_SECTION, self.KEY_VAULT_URI, key_vault_uri)

    def verify(self):
        # defining a list of config variables that are required to be set.
        azure_required_configurations = ['azure_client_id', 'azure_subscription_id', 'azure_tenant_id', 'key_vault_uri']

        required_params = dict(common=self.common_required_configurations, azure=azure_required_configurations)

        def verify_param():
            if not getattr(self, param, None):
                raise RuntimeError("Config element '{0}' is not configured! Please edit your config file: {1}"
                                   .format(getattr(self, param.upper()), self.filename))

        # verifying required configuration parameters
        for section in required_params:
            for param in required_params[section]:
                verify_param()
