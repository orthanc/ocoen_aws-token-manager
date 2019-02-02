import io
import os
import os.path

from enum import Enum
from configparser import ConfigParser
from getpass import getpass
from pykeepass import PyKeePass

from ocoen import filesecrets


class FileFormat(Enum):
    CONFIG = 'config'
    CREDENTIALS = 'credentials'
    ENCRYPTED_CREDENTIALS = 'encrypted_credentials'
    KEEPASS = 'keepass'


class FileDef(object):
    def __init__(self, fmt, base_def=None, suffix=None, env_name=None, path=None):
        self.fmt = fmt
        self.base_def = base_def
        self.suffix = suffix
        self.env_name = env_name
        self._path = path

    @property
    def path(self):
        path = None
        if self.env_name:
            path = os.environ.get(self.env_name)
        if not path:
            if self._path:
                path = self._path
            else:
                path = self.base_def.path + self.suffix
        return os.path.expanduser(path)

    @property
    def exists(self):
        return os.path.exists(self.path)

    @property
    def is_import_target(self):
        if self.fmt == FileFormat.ENCRYPTED_CREDENTIALS:
            return True
        elif self.fmt == FileFormat.KEEPASS and self.exists:
            # Can't create keepass files yet, so if a keypass file is present default to
            # importing into that. If not, create a filesecrets valult
            return True
        return False


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


class ConfigCredentialsFile:
    def __init__(self, config_file, profile):
        self._config_file = config_file
        self._profile = profile
        self.basename = config_file.basename
        self.exists = config_file.exists

    def get_credentials(self):
        section = self._config_file.get_profile_section(self._profile)
        if not section:
            return None

        access_key = section.get('aws_access_key_id')
        secret_key = section.get('aws_secret_access_key')
        token = section.get('aws_session_token')
        if not (access_key and secret_key):
            return None

        ret = {
            'aws_access_key_id': access_key,
            'aws_secret_access_key': secret_key,
        }
        if token:
            ret['aws_session_token'] = token,
        return ret

    def set_credentials(self, credentials):
        self._config_file.new_config()
        self._config_file.new_profile_section(self._profile, credentials)
        self._config_file.save()

    def update_credentials(self, access_key_id, secret_access_key):
        section = self._config_file.get_profile_section(self._profile)
        section['aws_access_key_id'] = access_key_id
        section['aws_secret_access_key'] = secret_access_key
        if 'aws_session_token' in section:
            del section['aws_session_token']
        self._config_file.save()

    def remove_credentials(self):
        section = self._config_file.get_profile_section(self._profile)
        for k in ['aws_access_key_id', 'aws_secret_access_key', 'aws_session_token']:
            if k in section:
                del section[k]
        self._config_file.save()


class KeepassCredentialsFile:
    def __init__(self, path, profile):
        self._path = path
        self._profile = profile
        self._keepass = None
        self.basename = os.path.basename(path)
        self.exists = os.path.exists(path)

    def _get_keepass(self):
        if not self.exists:
            return None
        if not self._keepass:
            password = getpass(prompt='Password for {0}: '.format(self.basename))
            self._keepass = PyKeePass(self._path, password=password)
        return self._keepass

    def get_credentials(self):
        keepass = self._get_keepass()
        if not keepass:
            return None
        entry = keepass.find_entries(
            path='AWS/' + self._profile + ' Access Key',
            first=True,
        )
        if not entry:
            return None

        return {
            'aws_access_key_id': entry.username,
            'aws_secret_access_key': entry.password,
        }

    def set_credentials(self, credentials):
        self.update_credentials(credentials['aws_access_key_id'], credentials['aws_secret_access_key'])

    def update_credentials(self, access_key_id, secret_access_key):
        keepass = self._get_keepass()
        aws_group = keepass.find_groups(path='AWS/', first=True)
        if not aws_group:
            aws_group = keepass.add_group(keepass.root_group, 'AWS')
        entry = keepass.find_entries(
            path='AWS/' + self._profile + ' Access Key',
            first=True,
        )
        if entry:
            entry.username = access_key_id
            entry.password = secret_access_key
        else:
            entry = keepass.add_entry(aws_group, self._profile + ' Access Key', access_key_id, secret_access_key)

        keepass.save()

    def remove_credentials(self):
        keepass = self._get_keepass()
        entry = keepass.find_entries(
            path='aws/' + self._profile + '-access_key',
            first=True,
        )
        if entry:
            keepass.delete_entry(entry)
            keepass.save()


def get_credential_files(*file_defs, profile):
    return [get_credential_file(file_def, profile) for file_def in file_defs]


def get_credential_file(file_def, profile):
    credential_file = _credential_files.get(file_def.path)
    if not credential_file:
        if file_def.fmt == FileFormat.KEEPASS:
            credential_file = KeepassCredentialsFile(file_def.path, profile)
        else:
            credential_file = ConfigCredentialsFile(get_config_file(file_def, profile), profile)
        _credential_files[file_def.path] = credential_file
    return credential_file


def get_config_file(file_def, profile):
    config_file = _config_files.get(file_def.path)
    if not config_file:
        prefix_sections = file_def.fmt == FileFormat.CONFIG
        encrypted = file_def.fmt == FileFormat.ENCRYPTED_CREDENTIALS
        config_file = ConfigFile(file_def.path, prefix_sections, encrypted, profile and profile.encode('UTF-8'))
        _config_files[file_def.path] = config_file
    return config_file


_config_files = {}
_credential_files = {}
