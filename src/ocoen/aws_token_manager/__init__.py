import argparse
import os
# Importing readline makes input behave nicer (e.g. backspace works) so not actually unused
import readline  # NOQA
import sys
import time

from base64 import urlsafe_b64encode
from getpass import getpass

import boto3

from ocoen.aws_token_manager.config import FileDef, FileFormat, get_config_file, get_credential_file, get_credential_files
from ocoen.aws_token_manager.tty import confirm, if_tty, if_not_tty, tty, tty_input

__version__ = '0.3.0'


# See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html
shared_config_file_def = FileDef(FileFormat.CONFIG, env_name='AWS_CONFIG_FILE', path=os.path.join('~', '.aws', 'config'))
shared_credentials_file_def = FileDef(FileFormat.CREDENTIALS, env_name='AWS_SHARED_CREDENTIALS_FILE', path=os.path.join('~', '.aws', 'credentials'))

shared_config_file = get_config_file(shared_config_file_def, None)


def _export_token(token):
    print("export AWS_ACCESS_KEY_ID='" + token['AccessKeyId'] + "';")
    print("export AWS_SECRET_ACCESS_KEY='" + token['SecretAccessKey'] + "';")
    print("export AWS_SESSION_TOKEN='" + token['SessionToken'] + "';")
    print("export AWS_SESSION_EXPIRY='" + str(token['Expiration'].astimezone(tz=None)) + "';")


def _create_session_for_iam(base_credentials, profile):
    static_session = boto3.Session(**base_credentials)
    mfa_device = _get_mfa_device(static_session, profile)
    if not mfa_device:
        # Session tokens can only call IAM APIs if they're created with MFA, so if no MFA just use the base credentials
        return static_session
    # If there is MFA, assume it protects the issuing of new keys, so create session credentials
    token = _obtain_session_token(static_session, mfa_device, 900)
    return boto3.Session(
                            aws_access_key_id=token['AccessKeyId'],
                            aws_secret_access_key=token['SecretAccessKey'],
                            aws_session_token=token['SessionToken']
                        )


def _obtain_session_token(session, mfa_device, duration):
    args = {}
    if mfa_device:
        mfa_code = tty_input('MFA Token: ')
        args['SerialNumber'] = mfa_device
        args['TokenCode'] = mfa_code
    if duration:
        args['DurationSeconds'] = int(duration)

    return session.client('sts').get_session_token(**args)['Credentials']


def _assume_role(session, role_arn, mfa_device, duration, role_config):
    args = {
        'RoleArn': role_arn,
        'RoleSessionName': role_config.get('session_name', 'AWS-CLI-session-{0}'.format(int(time.time())))
    }
    if 'external_id' in role_config:
        args['ExternalId'] = role_config['external_id']
    if mfa_device:
        mfa_code = tty_input('MFA Token: ')
        args['SerialNumber'] = mfa_device
        args['TokenCode'] = mfa_code
    if duration:
        args['DurationSeconds'] = int(duration)

    return session.client('sts').assume_role(**args)['Credentials']


def _get_mfa_device(session, profile):
    profile_config = shared_config_file.get_profile_section(profile)
    if profile_config and profile_config.get("mfa_serial"):
        return profile_config.get("mfa_serial")
    # CurrentUser() is not used because it requiers the GetUser permission, futher
    # CurrentUser().mfa_devices is used the user must be grated ListMFADevices for * which is undesirable
    mfa_devices = list(session.resource('iam').User(_get_current_username(session)).mfa_devices.all())
    if mfa_devices:
        return mfa_devices[0].serial_number
    return None


def _get_current_username(session):
    caller_identity = session.client('sts').get_caller_identity()
    # Parse the ARN rather than looking up the user by id since looking up the user
    # requires the additional GetUser permission
    arn = caller_identity['Arn']
    name_part = arn.split(':')[-1]
    return name_part.split('/', 1)[1]


def _get_base_credentials(profile, credential_file_defs=None, exit_if_none=True):
    if not credential_file_defs:
        credential_file_defs = _get_credential_file_defs(profile)[0]
    profile_config = shared_config_file.get_profile_section(profile) or {}
    credential_files = get_credential_files(*credential_file_defs, profile=profile, profile_config=profile_config)
    credentials_gen = ((f.get_credentials(), f) for f in credential_files)
    base_credentials = next((x for x in credentials_gen if x[0]), None)
    if base_credentials:
        return base_credentials
    if exit_if_none:
        sys.exit('No static access credentals found for profile {0}.'.format(profile))
    return None, None


@if_not_tty(prompt='Output is a terminal. Did you mean to run \'eval $(atm)\' instead ?\nDo you really want to write the access tokens? (Y/N): ')
def obtain_and_export_token(args):
    profile = args.profile
    profile_config = shared_config_file.get_profile_section(profile) or {}
    role_arn, source_profile = profile_config.get('role_arn'), profile_config.get('source_profile')
    check_source_profile = role_arn and source_profile
    base_credentials = _get_base_credentials(profile, exit_if_none=not check_source_profile)[0]
    if not base_credentials and check_source_profile:
        base_credentials = _get_base_credentials(source_profile, exit_if_none=True)[0]

    session = boto3.Session(**base_credentials)
    mfa_device = _get_mfa_device(session, profile)
    duration_seconds = args.life or profile_config.get('duration_seconds')
    if role_arn:
        token = _assume_role(session, role_arn, mfa_device, duration_seconds, profile_config)
    else:
        token = _obtain_session_token(session, mfa_device, duration_seconds)

    _export_token(token)
    with tty():
        if role_arn:
            print('Role Assumed, valid til: {0}'.format(token['Expiration'].astimezone(tz=None)))
        else:
            print('Token Obtained, valid til: {0}'.format(token['Expiration'].astimezone(tz=None)))


@if_tty(error_message='stdin and stdout must be a tty when importing credentials.')
def import_credentials(args):
    profile = args.profile
    profile_config = dict(shared_config_file.get_profile_section(profile)) or {}
    config_updates = {}
    credential_file_defs, file_specified = _get_credential_file_defs(profile, include_all=True)
    if args.target_file:
        target_def = _build_file_def(args.target_file)
        if not file_specified or target_def.path != credential_file_defs[0].path:
            config_updates['credentials_file'] = target_def.path
    elif file_specified:
        target_def = credential_file_defs[0]
    else:
        target_def = next((d for d in credential_file_defs if d.is_import_target))
    other_credential_file_defs = [d for d in credential_file_defs if d.path != target_def.path]
    if args.target_access_key_path:
        if args.target_access_key_path != profile_config.get('access_key_path'):
            config_updates['access_key_path'] = args.target_access_key_path
        profile_config['access_key_path'] = args.target_access_key_path
    target_credentials_file = get_credential_file(target_def, profile, profile_config)
    if target_credentials_file.exists:
        if target_def.fmt == FileFormat.KEEPASS:
            if (target_credentials_file.get_credentials()
                    and not confirm('{0} already has credentials for {1}, do you want to replace them? (Y/N): '.format(target_credentials_file.basename, profile))):
                sys.exit('Aborted')
        elif not confirm('{0} exists, do you want to replace it? (Y/N): '.format(target_credentials_file.basename)):
            sys.exit('Aborted')
    base_credentials, credential_file = _get_base_credentials(profile, other_credential_file_defs)

    if not confirm('Import credentials from {0} into {1}? (Y/N): '.format(credential_file.basename, target_credentials_file.basename)):
        return

    target_credentials_file.set_credentials(base_credentials)
    print('Access key encrypted into {0}'.format(target_credentials_file.basename))

    if not confirm('Do you want to remove the credentials from {0} (you may loose comments and formatting)? (Y/N): '.format(credential_file.basename)):
        return
    credential_file.remove_credentials()
    print('Access key removed from {0}'.format(credential_file.basename))

    if (config_updates and confirm('Do you want to update profile config to use the imported key '
                                   + '(you may loose comments and formatting)? (Y/N): ')):
        shared_config_file.update_profile_section(profile, config_updates)
        shared_config_file.save()


    if not confirm('Do you want to rotate the access keys now? (Y/N): '):
        return
    rotate_credentials(args)


def _ensure_single_access_key(user, base_credentials):
    inuse_access_key_id = base_credentials['aws_access_key_id']
    access_keys = list(user.access_keys.all())

    inuse_access_key = next((key for key in access_keys if key.access_key_id == inuse_access_key_id))
    other_access_key = next((key for key in access_keys if key.access_key_id != inuse_access_key_id), None)

    if other_access_key:
        if confirm('User {username} already has 2 access keys, delete key {access_key_id} created on {created}? (Y/N): '.format(
                    username=user.user_name,
                    access_key_id=other_access_key.access_key_id,
                    created=other_access_key.create_date,
                )):
            other_access_key.delete()
        else:
            sys.exit('Aborted')
    return inuse_access_key


@if_tty(error_message='stdin and stdout must be a tty when rotating credentials.')
def rotate_credentials(args):
    profile = args.profile
    base_credentials, credential_file = _get_base_credentials(profile)
    session = _create_session_for_iam(base_credentials, profile)
    iam = session.resource('iam')
    username = _get_current_username(session)
    user = iam.User(username)

    if getattr(args, 'change_password', False):
        current_password = credential_file.get_password(username)
        if args.prompt_password or not current_password:
            current_password = getpass(prompt='Current Password for {0}: '.format(username))
        new_password = getpass(prompt='New Password for {0} (Leave blank to generate): '.format(username))
        if new_password:
            if new_password != getpass(prompt='Confirm New Password for {0}: '.format(username)):
                raise RuntimeError('Passwords for {0} don\'t match!'.format(username))
        else:
            new_password = urlsafe_b64encode(os.urandom(30)).decode('ASCII')

        iam_client = session.client('iam')
        iam_client.change_password(OldPassword=current_password, NewPassword=new_password)
        try:
            credential_file.set_password(username, new_password)
        except Exception as e:
            print('ERROR Saving new password, new password is \'{0}\'.'.format(new_password))
            raise e
        print('IAM password for {0} changed.'.format(username))

    inuse_access_key = _ensure_single_access_key(user, base_credentials)
    new_access_key = user.create_access_key_pair()
    credential_file.update_credentials(new_access_key.access_key_id, new_access_key.secret_access_key)
    inuse_access_key.delete()
    print('Access key rotated')


def _get_credential_file_defs(profile, include_all=False):
    profile_config = shared_config_file.get_profile_section(profile)
    credentials_file = profile_config and profile_config.get('credentials_file')
    if credentials_file:
        credentials_files = [_build_file_def(credentials_file)]
        if not include_all:
            return credentials_files, True
    else:
        credentials_files = []
    return credentials_files + [
        FileDef(FileFormat.KEEPASS, base_def=shared_credentials_file_def, suffix='-{profile}.kdbx'.format(profile=profile)),
        FileDef(FileFormat.ENCRYPTED_CREDENTIALS, base_def=shared_credentials_file_def, suffix='-{profile}.enc'.format(profile=profile)),
        FileDef(FileFormat.KEEPASS, base_def=shared_credentials_file_def, suffix='.kdbx'),
        shared_config_file_def,
        shared_credentials_file_def,
    ], bool(credentials_file)


def _build_file_def(path):
    file_format = None
    if path.endswith('.enc'):
        file_format = FileFormat.ENCRYPTED_CREDENTIALS
    elif path.endswith('.kdbx'):
        file_format = FileFormat.KEEPASS
    return FileDef(file_format, path=path)


@if_not_tty(prompt='Output is a terminal.\nDo you really want to export the access tokens? (Y/N): ')
def export_credentials(args):
    profile = args.profile
    base_credentials, credential_file = _get_base_credentials(profile)
    print('# Exported from {0}'.format(credential_file.basename))
    print('[{0}]'.format(profile))
    print('aws_access_key_id = {0}'.format(base_credentials['aws_access_key_id']))
    print('aws_secret_access_key = {0}'.format(base_credentials['aws_secret_access_key']))
    if 'aws_session_token' in base_credentials:
        print('aws_session_token = {0}'.format(base_credentials['aws_session_token']))


def _add_profile_argument(parser, default):
    parser.add_argument('--profile', default=default,
                        help='The profile to work with. Defaults to the AWS_PROFILE environment variable or "default".')


def main():
    parser = argparse.ArgumentParser()
    _add_profile_argument(parser, default=os.environ.get('AWS_PROFILE', 'default'))
    parser.add_argument('--life', '-t', type=int,
                        help='How long the token should be valid for, default is token type specific. Attempting to '
                             + 'specify a length longer than the max allowed results in an error.')
    subparsers = parser.add_subparsers(title='Management Commands', dest='command',
                                       description='Commands for managing the static access credentials.')

    i_parser = subparsers.add_parser('import',
                                     help='Import the static access credentials from an existing credentials file into '
                                          + 'an encrypted credentials file.')
    # Profile is added again so it shows up in sub command help and can be
    # specified after the subcommand as well as before
    _add_profile_argument(i_parser, default=argparse.SUPPRESS)
    i_parser.add_argument('--target-file', '-f',
                          help='Specify the path of the encrypted file to import the credentials into.')
    i_parser.add_argument('--target-access-key-path',
                          help='Specify the path within the encrypted file where the access keys should be stored. '
                               + 'This is only supported for KeePass files and allows you to control which group '
                               + 'and entry will be used.')

    r_parser = subparsers.add_parser('rotate',
                                     help='Rotate the static access credentials so that new credentials are in use.')
    r_parser.add_argument('--change-password', action='store_true',
                          help='Change the IAM user\'s password as well as rotating the access keys. '
                               + 'This is only supported for KeePass files.')
    r_parser.add_argument('--prompt-password', action='store_true',
                          help='When --change-password is specified, prompt for the current password even if there '
                               + 'is already a saved password.')
    # Profile is added again so it shows up in sub command help and can be
    # specified after the subcommand as well as before
    _add_profile_argument(r_parser, default=argparse.SUPPRESS)

    e_parser = subparsers.add_parser('export',
                                     help='Export the static access credentials to stdout.')
    # Profile is added again so it shows up in sub command help and can be
    # specified after the subcommand as well as before
    _add_profile_argument(e_parser, default=argparse.SUPPRESS)

    args = parser.parse_args()
    if not args.command:
        obtain_and_export_token(args)
    elif args.command == 'import':
        import_credentials(args)
    elif args.command == 'rotate':
        rotate_credentials(args)
    elif args.command == 'export':
        export_credentials(args)
