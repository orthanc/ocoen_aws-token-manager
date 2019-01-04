import os
import os.path
# Importing readline makes input behave nicer (e.g. backspace works) so not actually unused
import readline  # NOQA

from configparser import ConfigParser
from getpass import getpass

from ocoen import filesecrets

config_files = {}


class ConfigFile(object):
    def __init__(self, path, prefix_sections):
        self.path = path
        self.prefix_sections = prefix_sections
        self.exists = os.path.exists(path)
        self._config = None

    def get_config(self):
        if not self.exists:
            return None
        if not self._config:
            with open(self.path, 'rb') as f:
                data = f.read()
            if filesecrets.is_encrypted(data):
                password = getpass(prompt='Password for {0}:'.format(os.path.basename(self.path)))
                data = filesecrets.decrypt(data, password)
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


def get_config_file(path, prefix_sectiions):
    if path not in config_files:
        config_files[path] = ConfigFile(path, prefix_sectiions)
    return config_files[path]


shared_config_file = get_config_file(os.environ.get('AWS_CONFIG_FILE', os.path.expanduser(os.path.join('~', '.aws', 'config'))), True)
shared_credentials_file = get_config_file(os.environ.get('AWS_SHARED_CREDENTIALS_FILE', os.path.expanduser(os.path.join('~', '.aws', 'credentials'))), False)


def get_profile_credentials_file(profile_name):
    return get_config_file('{0}-{1}.enc'.format(shared_credentials_file.path, profile_name), False)
