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
import importlib
import json
import os

CLOUDS = ['aws', 'azure']


class MesserCommandLoader(object):

    def __init__(self, cloud, module):
        if cloud not in CLOUDS:
            raise RuntimeError("Unknown Cloud {}".format(cloud))
        self._cloud = cloud
        self._module = importlib.import_module(module)

    @property
    def cloud(self):
        return self._cloud

    @property
    def module(self):
        return self._module

    def _get_cloud_specific_name(self, class_name_template):
        if self.cloud == 'aws':
            return class_name_template.format(cloud="AWS")
        elif self.cloud == 'azure':
            return class_name_template.format(cloud="Azure")

    def load(self, class_name_template, args):
        class_name = self._get_cloud_specific_name(class_name_template)
        if hasattr(self.module, class_name):
            class_ = getattr(self.module, class_name)
            return class_(args)
        raise RuntimeError("{} has no class named {}".format(self.module, class_name))


def overwrite_data_bag_item(cloud, bag, item, key, messer_config):
    filename = write_item_to_disk(item)
    try:
        args = messer.parse_args(['data', 'bag', 'from', 'file', cloud, bag, filename, '--secret-file', key, '-c', messer_config.name, '--force'])
        cmd = MesserCommandLoader(cloud, 'messer.databag').load("Upload{cloud}DataBag", args)
        return cmd.execute()
    finally:
        os.remove(filename)


def create_data_bag_item(cloud, bag, item, key, messer_config):
    filename = write_item_to_disk(item)
    try:
        args = messer.parse_args(['data', 'bag', 'from', 'file', cloud, bag, filename, '--secret-file', key, '-c', messer_config.name])
        cmd = MesserCommandLoader(cloud, 'messer.databag').load("Upload{cloud}DataBag", args)
        return cmd.execute()
    finally:
        os.remove(filename)


def create_data_bag(cloud, bag, messer_config):
    args = messer.parse_args(['data', 'bag', 'create', cloud, bag, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.databag').load("Create{cloud}DataBag", args)
    return cmd.execute()


def decrypt_databag_item(cloud, bag, item, messer_config):
    args = messer.parse_args(['data', 'bag', 'show', cloud, bag, item, '-c', messer_config.name, '--decrypt'])
    cmd = MesserCommandLoader(cloud, 'messer.databag').load("Show{cloud}DataBag", args)
    return cmd.execute()


def list_databag_items(cloud, bag, messer_config):
    args = messer.parse_args(['data', 'bag', 'show', cloud, bag, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.databag').load("Show{cloud}DataBag", args)
    return cmd.execute()


def list_databags(cloud, messer_config):
    args = messer.parse_args(['data', 'bag', 'show', cloud, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.databag').load("Show{cloud}DataBag", args)
    return cmd.execute()


def list_envelope_keys(cloud, messer_config):
    args = messer.parse_args(['encryption', 'list', cloud, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.encryption').load("List{cloud}EncryptionKeys", args)
    return cmd.execute()

def list_envelope_key_versions(cloud, messer_config, key_name):
    args = messer.parse_args(['encryption', 'list', cloud, key_name, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.encryption').load("List{cloud}EncryptionKeys", args)
    return cmd.execute()


def create_envelope_key(cloud, key_name, messer_config):
    args = messer.parse_args(['encryption', 'create', cloud, key_name, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.encryption').load("Create{cloud}EncryptionKey", args)
    return cmd.execute()


def increment_envelope_key(cloud, key_name, messer_config):
    args = messer.parse_args(['encryption', 'increment', cloud, key_name, '-c', messer_config.name])
    cmd = MesserCommandLoader(cloud, 'messer.encryption').load("Increment{cloud}KeyVersion", args)
    return cmd.execute()


def decrypt_databag_items(items, cloud, bag, config):
    return [decrypt_databag_item(cloud, bag, item, config) for item in items]


def remove_key_info(item):
    return {'name': item.pop('key_name'), 'version': item.pop('key_version')}


def write_item_to_disk(item):
    with open('item.json', 'w') as f:
        f.write(json.dumps(item))
    return 'item.json'
