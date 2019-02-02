import io
import os
import os.path

from enum import Enum
from configparser import ConfigParser
from getpass import getpass

from ocoen import filesecrets

config_files = {}


class FileFormat(Enum):
    CONFIG = 'config'
    CREDENTIALS = 'credentials'
    ENCRYPTED_CREDENTIALS = 'encrypted_credentials'


class ConfigFile(object):
    def __init__(self, path, prefix_sections, encrypted, additional_data=None):
        self.path = path
        self.prefix_sections = prefix_sections
        self.encrypted = encrypted
        self.additional_data = additional_data
        self.basename = os.path.basename(path)
        self.exists = os.path.exists(path)
        self._config = None
        self._password = None

    def new_config(self):
        self._config = ConfigParser(default_section=None)
        return self._config

    def _get_password(self, confirm=False):
        if not self._password:
            self._password = getpass(prompt='Password for {0}: '.format(self.basename))
            if confirm and self._password != getpass(prompt='Confirm Password for {0}: '.format(self.basename)):
                raise RuntimeError('Passwords for {0} don\'t match!'.format(self.basename))
        return self._password

    def get_config(self):
        if not self._config:
            if not self.exists:
                return None
            with open(self.path, 'rb') as f:
                data = f.read()
            if self.encrypted:
                data = filesecrets.decrypt(data, self._get_password(), self.additional_data)
            self._config = ConfigParser(default_section=None)
            self._config.read_string(data.decode(), self.path)
        return self._config

    def save(self):
        with io.StringIO() as f:
            self._config.write(f)
            data = f.getvalue().encode()
        if self.encrypted:
            data = filesecrets.encrypt(data, self._get_password(True), self.additional_data)
        with open(self.path, 'wb') as f:
            f.write(data)

    def new_profile_section(self, profile_name, content={}):
        config = self.get_config()
        if not config:
            return None
        section_name = self._get_profile_section_name(profile_name)
        config[section_name] = content.copy()

    def get_profile_section(self, profile_name):
        config = self.get_config()
        if not config:
            return None
        section_name = self._get_profile_section_name(profile_name)
        if section_name in config:
            return config[section_name]
        return None

    def _get_profile_section_name(self, profile_name):
        if profile_name == 'default':
            return 'default'
        elif self.prefix_sections:
            return 'profile ' + profile_name
        else:
            return profile_name


def get_config_file(path, file_format, additional_data=None):
    if path not in config_files:
        prefix_sections = file_format == FileFormat.CONFIG
        encrypted = file_format == FileFormat. ENCRYPTED_CREDENTIALS
        config_files[path] = ConfigFile(path, prefix_sections, encrypted, additional_data)
    return config_files[path]


shared_config_file = get_config_file(
    path=os.environ.get('AWS_CONFIG_FILE', os.path.expanduser(os.path.join('~', '.aws', 'config'))),
    file_format=FileFormat.CONFIG,
)
shared_credentials_file = get_config_file(
    path=os.environ.get('AWS_SHARED_CREDENTIALS_FILE', os.path.expanduser(os.path.join('~', '.aws', 'credentials'))),
    file_format=FileFormat.CREDENTIALS,
)


def get_profile_credentials_file(profile_name):
    return get_config_file(
        path='{0}-{1}.enc'.format(shared_credentials_file.path, profile_name),
        file_format=FileFormat.ENCRYPTED_CREDENTIALS,
        additional_data=profile_name.encode('UTF-8'),
    )
