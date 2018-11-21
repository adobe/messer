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
import appdirs
import os
import shutil
from messer import databag, configure, encryption, bulk


ROOT = os.path.abspath(os.path.dirname(__file__))


def get_config_dir():
    """
    Gets the full path of the platform specific user based config directory.

    :return: Return full path to the user-specific config dir (based on operating the system) for this application.
    """
    return appdirs.user_config_dir("messer")


def get_default_config():
    """
    If the config parameter was not passed to messer, use the default that was installed as part of the installation.

    :return: The default configuration file created during setup.
    :type return: str
    """
    installed_file = os.path.join(get_config_dir(), 'messer.ini')
    if os.path.exists(installed_file):
        return installed_file
    else:
        os.makedirs(get_config_dir())
        template = os.path.join(ROOT, 'messer.ini')
        if os.path.exists(template):
            shutil.copyfile(template, os.path.join(get_config_dir(), 'messer.ini'))
        else:
            raise RuntimeError("The config template was not installed!")

    if not os.path.exists(installed_file):
        raise RuntimeError("Failed to initialize config file from template")


def parse_args(args):
    """
    The argument parser for messer. Options for the individual positional arguments are defined in their respective
    files.

    :return: The arguments passed to messer.
    :type Namespace
    """
    root_parser = argparse.ArgumentParser(prog="messer")
    subparsers = root_parser.add_subparsers(help='Available Commands')
    databag.options(subparsers)
    configure.options(subparsers)
    encryption.options(subparsers)
    bulk.options(subparsers)

    return root_parser.parse_args(args)


def main():
    """
    This is the main method of the application.

    :return: None
    """
    args = parse_args(None)
    command = args.command(args)
    command.execute()
