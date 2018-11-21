MESSER
=====================================

Messer is a command line tool that was initially designed to be used as a replacement for chef's 'knife' tool for
creating / fetching secrets.  Messer uses envelope encryption with KMS + AWS S3 or Azure Vault to encrypt secrets.
You can find our documentation [here](docs/docs.md).

Why use Messer?
-------
This section tries to address the advantages in using Messer and describes the philosophy behind the inception of this tool. As already stated, Messer is a replacement for chef's 'knife' tool for handling data bags and addresses some of the issues that were perceived as a threat for the consumption of 'knife' to handle secrets of a highly secure and compliant service.

1. Envelope Encryption: Messer uses envelope encryption to secure not only the actual sensitive data but also the keys to be used for such encryptions. The key used for encrypting the sensitive data is called the Data Key and the key used to encrypt the Data key is called the master key. For both of the cloud providers supported, Messer uses the providers native API to decrypt the data key using the master key and thus never handles or stores the master key in its AWS S3 buckets or Azure Store Secrets.

1. Multi Cloud: Messer is a useful tool for handling secrets in case of services which need to be multi cloud and run on both AWS and Azure. Migrating secrets from one cloud to another is also very easy using the bulk commands of Messer.

1. Secure: Messer always ensures that both Data Keys and Secrets are always encrypted at rest and are only in their decrypted form in memory. For both of the cloud providers that are supported, Messer uses the providers native API to decrypt the data key using the master key and thus never handles or stores the master key in its AWS S3 buckets or Azure Store Secrets.

1. Cross Platform: Messer is packaged as a python library and hence is portable between Unix/Linux servers and also Windows servers. Messer has been tested on both of these families of operating systems.

Cryptographic Key Details
-------
To know more about about how the cryptographic keys are handled, refer to the following sections:
1. [AWS](/docs/aws.md#cryptographic-key-details-in-aws)
1. [Azure](/docs/azure.md#cryptographic-key-details-in-azure)


Installation
-------
```bash
# after checking out the source code from GIT
cd messer
python setup.py install
```

Messer will install a default configuration file at an OS specific setting as defined by the `argparse` library.
Use the `configure` command to view, set or create a new configuration file at a custom location. Messer will always
use the default configuration file unless you override it by passing the `-c` argument to each command.

Help
-------
Messer has built in help for all the sub commands it is configured to run on. To begin with, run:
```bash
messer --help
```

Running The Tests
-------
* Check out the guide for [running tests on AWS.](/docs/aws.md#running-tests)
* Check out the guide for [running tests on Azure.](/docs/azure.md#running-tests)

CONTRIBUTING TO MESSER
-------

Contributions are of course welcome! Please take a look at our [Contributing Guide](.github/CONTRIBUTING.md)

Security Issues
-------

Security issues shouldn't be reported on this issue tracker. Instead, [file an issue to our security experts](https://helpx.adobe.com/security/alertus.html)

License
-------

This project is licensed under the Apache V2 License. See [LICENSE](/LICENSE) for more information.
