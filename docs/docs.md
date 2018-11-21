Messer Documentation
====================

Messer is a secrets management/injection tool written in python.  You can install Messer locally by checking out the source code and executing `setup.py`.

**Installation**
```bash
# after checking out the source code from GIT
cd messer
python setup.py install
```

Messer will install a default configuration file at an OS specific setting as defined by the `argparse` library.
Use the `configure` command to view, set or create a new configuration file at a custom location. Messer will always
use the default configuration file unless you override it by passing the `-c` argument to each command.

Click on the links below to find out more about how Messer works.


[Messer on AWS](aws.md)

[Messer on Azure](azure.md)

[Messer Bulk Commands](bulk.md)
