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
import messer
from abstracts import MesserAWSCommand, MesserAzureCommand

def set_common_cloud_provider_options(provider_args):
    provider_args.add_argument('-m', '--master-key', help="The Cloud specific master key name or alias that should be  "
                                                          "used when creating new envelope encryption keys.")
    provider_args.add_argument('--silent', action='store_true', help="Suppress all print statements from Messer.")
    provider_args.add_argument('-e', '--tier', help="The service tier you are operating on. dev | stage | prod")
    provider_args.add_argument('-p', '--print-config', action='store_true', help="Print the current configuration")
    provider_args.add_argument('-c', '--config', default=messer.get_default_config(), type=argparse.FileType('a'),
                               help="The configuration file to use.")

def options(subparser):
    """
    Specifies the options for the 'messer configure' command. Arguments that call the set_defaults method, will call a
    function with the specified name and pass the parsed args to it. Anything that the method returns is assigned to
    the property 'command'.

    :param subparser: A sub parser object that these options can be added to.
    :type subparser: SubArgumentParser
    :return: None
    """
    configure = subparser.add_parser('configure', help='Configure Commands')
    cloud_specific_configure = configure.add_subparsers(help='Cloud Provider specific configuration.')

    # AWS specific configuration options.
    aws_configure = cloud_specific_configure.add_parser('aws', help='AWS Configuration')
    aws_configure.set_defaults(command=configure_messer_aws)
    set_common_cloud_provider_options(aws_configure)

    aws_configure.add_argument('-b', '--secrets-bucket', help="Configure S3 bucket where messer will look for secrets")
    aws_configure.add_argument('-f', '--secrets-folder', help="The sub-folder in the secrets bucket to store secrets. "
                                                             "Note that if TIER is also set, this will be a sub-folder"
                                                             "of TIER.")
    aws_configure.add_argument('-x', '--encryption-context', help="The encryption context for encrypting/decrypting")
    aws_configure.add_argument('-k', '--keys-bucket', help="Configure the bucket _name where messer will look for keys")
    aws_configure.add_argument('-a', '--role-arn', help="The arn of the role you want messer to assume")
    aws_configure.add_argument('-s', '--role-session-name', help="The session name to use when assuming roles")
    aws_configure.add_argument('-n', '--aws-profile', help="Name of aws profile to use(defined in ~/.aws/credentials).")
    aws_configure.add_argument('-r', '--region', help="The AWS region name to use. I.e 'us-east-1'.")


    # Azure specific configuration options.
    azure_configure = cloud_specific_configure.add_parser('azure', help='Azure Configuration')
    azure_configure.set_defaults(command=configure_messer_azure)
    set_common_cloud_provider_options(azure_configure)

    azure_configure.add_argument('-s', '--azure-subscription-id', help="Azure Subscription ID.")
    azure_configure.add_argument('-t', '--azure-tenant-id', help="Azure Tenant ID.")
    azure_configure.add_argument('-n', '--azure-client-id', help="Azure Client ID.")
    azure_configure.add_argument('-u', '--azure-key-vault-uri', help="Azure Key Vault URI.")


class Configure(object):
    """
    Messer configure command Interface.
    """

    def __init__(self):
        super(Configure, self).__init__()

    def save_config(self, args, config):
        """
        Common code across cloud providers for configuring Messer.
        """
        # setting common config variables
        if args.master_key:
            config.master_key = args.master_key

        if args.tier:
            config.tier = args.tier

        if args.silent:
            config.silent = args.silent

        config.save()
        print("Saved configuration to {0}".format(config.filename))
        if args.print_config:
            config.display()


class AzureConfigure(MesserAzureCommand, Configure):
    """
    A messer command method for configuring the default (or specified) ini file from the command line for Azure
    """

    def __init__(self, args):
        super(AzureConfigure, self).__init__(args, init_conn=False)
        self.config.pre_process([self.config.MESSER_AZURE_SECTION])

    def execute(self):
        # Azure specific config
        if self.args.azure_client_id:
            self.config.azure_client_id = self.args.azure_client_id
        if self.args.azure_subscription_id:
            self.config.azure_subscription_id = self.args.azure_subscription_id
        if self.args.azure_tenant_id:
            self.config.azure_tenant_id = self.args.azure_tenant_id
        if self.args.azure_key_vault_uri:
            self.config.key_vault_uri = self.args.azure_key_vault_uri

        self.save_config(self.args, self.config)


class AWSConfigure(MesserAWSCommand, Configure):
    """
    A messer command method for configuring the default (or specified) ini file from the command line for AWS.
    """

    def __init__(self, args):
        super(AWSConfigure, self).__init__(args, init_conn=False)
        self.config.pre_process([self.config.MESSER_AWS_SECTION])

    def execute(self):
        # AWS specific config
        if self.args.secrets_bucket:
            self.config.secrets_bucket = self.args.secrets_bucket
        if self.args.secrets_folder:
            self.config.secrets_folder = self.args.secrets_folder
        if self.args.keys_bucket:
            self.config.keys_bucket = self.args.keys_bucket
        if self.args.role_arn:
            self.config.role_arn = self.args.role_arn
        if self.args.role_session_name:
            self.config.role_session_name = self.args.role_session_name
        if self.args.encryption_context:
            self.config.encryption_context = self.args.encryption_context
        if self.args.aws_profile:
            self.config.aws_profile = self.args.aws_profile
        if self.args.region:
            self.config.region = self.args.region

        self.save_config(self.args, self.config)


# automatically called during options parsing.
def configure_messer_azure(args):
    return AzureConfigure(args)


def configure_messer_aws(args):
    return AWSConfigure(args)
