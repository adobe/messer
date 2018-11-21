MESSER
=====================================

Messer is command line tool that was initially designed to be used as a replacement for chef's 'knife' tool for
creating / fetching secrets.  Messer uses envelope encryption with KMS + AWS S3 or Azure Vault to encrypt secrets.
You can find our documentation [here](docs/docs.md).

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

Running The Tests
-------
* Check out the guide for [running tests on AWS.](/docs/aws.md#running-tests)
* Check out the guide for [running tests on Azure.](/docs/azure.md#running-tests)

CONTRIBUTING TO MESSER
-------

Contributions are of course welcome! Please take a look at our [Contributing Guide](.github/CONTRIBUTING.md)

License
-------

This project is licensed under the Apache V2 License. See [LICENSE](/LICENSE) for more information.
