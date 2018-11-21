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
from messer import utils
from messer.abstracts import MesserCommand


def common_options(parser):
    parser.add_argument('cloud', help="the cloud you're working with. {}".format(utils.CLOUDS))
    parser.add_argument('config', type=argparse.FileType('r'), help="The Messer config file.", )


def options(subparser):
    """
    Defines argument options for bulk operations. Arguments that call the set_defaults method, will call a function
    with the specified name and pass the parsed args to it. Anything that the method returns is assigned to the property
    'command'.

    :param subparser: A sub parser object that these options can be added to.
    :type subparser: SubArgumentParser
    :return: None
    """
    # bulk
    bulk = subparser.add_parser('bulk', help='Bulk Commands')
    bulk_parser = bulk.add_subparsers(help="Bulk Sub Commands")

    copy_options = bulk_parser.add_parser('copy', help="Recursively copy all data bags and their items from one env to another.")
    copy_options.add_argument('src_cloud', help="The source cloud. {}".format(utils.CLOUDS))
    copy_options.add_argument('dest_cloud', help="The destination cloud. {}".format(utils.CLOUDS))
    copy_options.add_argument('src_config', type=argparse.FileType('r'), help="The source Messer config file to copy secrets from.", )
    copy_options.add_argument('dest_config', nargs='+', type=argparse.FileType('r'), help="The destination Messer config file where the secrets will be copied to.")
    copy_options.set_defaults(command=copy)

    list_items = bulk_parser.add_parser('list', help="Recursively list all the data bags and items.")
    common_options(list_items)
    list_items.set_defaults(command=list_all)

    re_encrypt_options = bulk_parser.add_parser('re-encrypt', help="Recursively re-encrypt everything with the latest key version.")
    common_options(re_encrypt_options)
    re_encrypt_options.set_defaults(command=re_encrypt)

    rotate_options = bulk_parser.add_parser('rotate-keys', help="Recursivly rotate encryption keys and re-encrypt everything with the newly created key.")
    common_options(rotate_options)
    rotate_options.set_defaults(command=rotate_and_re_encrypt)


class CopyCommand(MesserCommand):

    def __init__(self, args):
        super(CopyCommand, self).__init__(args)
        self._src_cloud = args.src_cloud
        self._src_config = args.src_config
        self._dest_cloud = args.dest_cloud
        self._dest_config = args.dest_config

    @property
    def src_config(self):
        return self._src_config

    @property
    def src_cloud(self):
        return self._src_cloud

    @property
    def dest_config(self):
        return self._dest_config

    @property
    def dest_cloud(self):
        return self._dest_cloud

    def copy_data_bag_items(self, bag):
        items = utils.list_databag_items(self.src_cloud, bag, self.src_config)
        for item in utils.decrypt_databag_items(items, self.src_cloud, bag, self.src_config):
            key_info = utils.remove_key_info(item)
            utils.create_data_bag_item(self.dest_cloud, bag, item, key_info['name'], self.dest_config)
            print("Copied {}/{} from {} -> {} ."
                  .format(bag, item['id'], self.src_config, self.dest_config))

    def copy_data_bags(self, dest_config):
        bags = utils.list_databags(self.src_cloud, self.src_config)
        for bag in bags:
            utils.create_data_bag(self.dest_cloud, bag, dest_config)
            self.copy_data_bag_items(bag)

    def execute(self):
        for config in self.dest_config:
            self.copy_data_bags(config)


class ListAllCommand(MesserCommand):
    def __init__(self, args):
        super(ListAllCommand, self).__init__(args, config=args.config)
        self._cloud = args.cloud

    @property
    def cloud(self):
        return self._cloud

    def execute(self):
        bags = utils.list_databags(self.cloud, self.config)
        for bag in bags:
            print(bag)
            for item in utils.list_databag_items(self.cloud, bag, self.config):
                print("\t{}".format(item))


class ReEncryptCommand(MesserCommand):
    def __init__(self, args):
        super(ReEncryptCommand, self).__init__(args, config=args.config)
        self._cloud = args.cloud

    @property
    def cloud(self):
        return self._cloud

    def re_encrypt_items(self, items, bag):
        for item in utils.decrypt_databag_items(items, self.cloud, bag, self.config):
            key_info = utils.remove_key_info(item)
            utils.overwrite_data_bag_item(self.cloud, bag, item, key_info['name'], self.config)
            print("Re-encrypted {}/{} with latest key.".format(bag, item['id']))

    def execute(self):
        bags = utils.list_databags(self.cloud, self.config)
        for bag in bags:
            items = utils.list_databag_items(self.cloud, bag, self.config)
            self.re_encrypt_items(items, bag)


class RotateAndReEncryptCommand(MesserCommand):
    def __init__(self, args):
        super(RotateAndReEncryptCommand, self).__init__(args, config=args.config)
        self._cloud = args.cloud
        self.rotated_keys = []

    @property
    def cloud(self):
        return self._cloud

    def rotate_key(self, key_info):
        if key_info['name'] not in self.rotated_keys:
            print("Rotating {}".format(key_info['name']))
            new_version = utils.increment_envelope_key(self.cloud, key_info['name'], self.config)
            self.rotated_keys.append(key_info['name'])
            print("Rotated {}.\nPrevious Version:{}\nNew Version:{}"
                  .format(key_info['name'], key_info['version'], new_version))

    def re_encrypt_items(self, items, bag):
        for item in utils.decrypt_databag_items(items, self.cloud, bag, self.config):
            key_info = utils.remove_key_info(item)
            self.rotate_key(key_info)
            utils.overwrite_data_bag_item(self.cloud, bag, item, key_info['name'], self.config)
            print("Re-encrypted {}/{} with latest key.".format(bag, item['id']))

    def execute(self):
        bags = utils.list_databags(self.cloud, self.config)
        for bag in bags:
            items = utils.list_databag_items(self.cloud, bag, self.config)
            self.re_encrypt_items(items, bag)


def copy(args):
    return CopyCommand(args)


def list_all(args):
    return ListAllCommand(args)


def re_encrypt(args):
    return ReEncryptCommand(args)


def rotate_and_re_encrypt(args):
    return RotateAndReEncryptCommand(args)
