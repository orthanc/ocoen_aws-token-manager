import os
import os.path

from configparser import ConfigParser
from getpass import getpass

from ocoen import filesecrets

config_files = {}


class ConfigFile(object):
    def __init__(self, path, prefix_sections, encrypted=True, additional_data=None):
        self.path = path
        self.prefix_sections = prefix_sections
        self.encrypted = encrypted
        self.additional_data = additional_data
        self.exists = os.path.exists(path)
        self._config = None

    def get_config(self):
        if not self.exists:
            return None
        if not self._config:
            with open(self.path, 'rb') as f:
                data = f.read()
            if self.encrypted:
                password = getpass(prompt='Password for {0}: '.format(os.path.basename(self.path)))
                data = filesecrets.decrypt(data, password, self.additional_data)
            self._config = ConfigParser()
            self._config.read_string(data.decode(), self.path)
        return self._config

    def get_profile_section(self, profile_name):
        config = self.get_config()
        if not config:
            return None
        if profile_name == 'default':
            section_name = 'default'
        elif self.prefix_sections:
            section_name = 'profile ' + profile_name
        else:
            section_name = profile_name
        if section_name in config:
            return config[section_name]
        return None


def get_config_file(path, prefix_sections, encrypted=False, additional_data=None):
    if path not in config_files:
        config_files[path] = ConfigFile(path, prefix_sections, encrypted, additional_data)
    return config_files[path]


shared_config_file = get_config_file(os.environ.get('AWS_CONFIG_FILE', os.path.expanduser(os.path.join('~', '.aws', 'config'))), True)
shared_credentials_file = get_config_file(os.environ.get('AWS_SHARED_CREDENTIALS_FILE', os.path.expanduser(os.path.join('~', '.aws', 'credentials'))), False)


def get_profile_credentials_file(profile_name):
    return get_config_file('{0}-{1}.enc'.format(shared_credentials_file.path, profile_name), False,
                           encrypted=True, additional_data=profile_name.encode('UTF-8'))
