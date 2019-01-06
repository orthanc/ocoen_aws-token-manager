import os
# Importing readline makes input behave nicer (e.g. backspace works) so not actually unused
import readline  # NOQA
import sys
import argparse

import boto3

from ocoen.aws_token_manager import config
from ocoen.aws_token_manager.tty import confirm, if_tty, if_not_tty, tty, tty_input

# See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html
shared_config_files = [config.shared_config_file, config.shared_credentials_file]


def _export_token(token):
    print("export AWS_ACCESS_KEY_ID='" + token['AccessKeyId'] + "';")
    print("export AWS_SECRET_ACCESS_KEY='" + token['SecretAccessKey'] + "';")
    print("export AWS_SESSION_TOKEN='" + token['SessionToken'] + "';")


def _create_session_for_iam(base_credentials):
    static_session = boto3.Session(**base_credentials)
    mfa_device = _get_mfa_device(static_session)
    if not mfa_device:
        # Session tokens can only call IAM APIs if they're created with MFA, so if no MFA just use the base credentials
        return static_session
    # If there is MFA, assume it protects the issuing of new keys, so create session credentials
    token = _obtain_token(static_session, mfa_device, 900)
    return boto3.Session(
                            aws_access_key_id=token['AccessKeyId'],
                            aws_secret_access_key=token['SecretAccessKey'],
                            aws_session_token=token['SessionToken']
                        )


def _obtain_token(session, mfa_device, duration):
    args = {}
    if mfa_device:
        mfa_code = tty_input('MFA Token: ')
        args['SerialNumber'] = mfa_device
        args['TokenCode'] = mfa_code
    if duration:
        args['DurationSeconds'] = duration

    return session.client('sts').get_session_token(**args)['Credentials']


def _get_mfa_device(session):
    # CurrentUser().user is used because it limit listing of MFA devices by username. This allows the user to be
    # granted permission to list only their own MFA devices.
    # If CurrentUser().mfa_devices is used the user must be grated ListMFADevices for * which is undesirable
    mfa_devices = list(session.resource('iam').CurrentUser().user.mfa_devices.all())
    if mfa_devices:
        return mfa_devices[0].serial_number
    return None


def _get_base_credentials(credential_files, profile_name):
    sections = ((f, f.get_profile_section(profile_name)) for f in credential_files)
    credentials = ((f, _extract_credentials(section)) for f, section in sections if section)
    base_credentials = next(((creds, f) for f, creds in credentials if creds), None)
    if base_credentials:
        return base_credentials
    sys.exit('No static access credentals found.')


def _extract_credentials(section):
    access_key = section.get('aws_access_key_id', None)
    secret_key = section.get('aws_secret_access_key', None)
    token = section.get('aws_session_token', None)
    if not (access_key and secret_key):
        return None

    ret = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
    }
    if token:
        ret['aws_session_token'] = token,
    return ret


@if_not_tty(prompt='Output is a terminal. Did you mean to run \'eval $(atm)\' instead ?\nDo you really want to write the access tokens? (Y/N): ')
def obtain_and_export_token(args):
    profile = args.profile
    base_credentials = _get_base_credentials([config.get_profile_credentials_file(profile)] + shared_config_files, profile)[0]
    session = boto3.Session(**base_credentials)
    token = _obtain_token(session, _get_mfa_device(session), args.life)
    _export_token(token)
    with tty():
        print('Token Obtained, valid til: {0}'.format(token['Expiration'].astimezone(tz=None)))


@if_tty(error_message='stdin and stdout must be a tty when importing credentials.')
def import_credentials(args):
    profile = args.profile
    profile_credentials_file = config.get_profile_credentials_file(profile)
    if (profile_credentials_file.exists
            and not confirm('{0} exists, do you want to replace it? (Y/N): '.format(profile_credentials_file.basename))):
        sys.exit('Aborted')
    base_credentials, config_file = _get_base_credentials(shared_config_files, profile)

    profile_credentials_file.new_config()
    profile_credentials_file.new_profile_section(profile, base_credentials)
    profile_credentials_file.save()
    print('Access key encrypted into {0}'.format(profile_credentials_file.basename))

    if not confirm('Do you want to remove the credentials from {0} (you may loose comments and formatting)? (Y/N): '.format(config_file.basename)):
        return
    section = config_file.get_profile_section(profile)
    for k in base_credentials:
        del section[k]
    config_file.save()
    print('Access key removed from {0}'.format(config_file.basename))

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


@if_tty(error_message='stdin and stdout must be a tty when rotateing credentials.')
def rotate_credentials(args):
    profile = args.profile
    base_credentials, config_file = _get_base_credentials([config.get_profile_credentials_file(profile)] + shared_config_files, profile)
    session = _create_session_for_iam(base_credentials)
    iam = session.resource('iam')
    user = iam.CurrentUser().user

    inuse_access_key = _ensure_single_access_key(user, base_credentials)
    new_access_key = user.create_access_key_pair()
    section = config_file.get_profile_section(profile)
    section['aws_access_key_id'] = new_access_key.access_key_id
    section['aws_secret_access_key'] = new_access_key.secret_access_key
    if 'aws_session_token' in section:
        del section['aws_session_token']
    config_file.save()
    inuse_access_key.delete()
    print('Access key rotated')


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

    r_parser = subparsers.add_parser('rotate',
                                     help='Rotate the static access credentials so that new credentials are in use.')
    # Profile is added again so it shows up in sub command help and can be
    # specified after the subcommand as well as before
    _add_profile_argument(r_parser, default=argparse.SUPPRESS)

    args = parser.parse_args()
    if not args.command:
        obtain_and_export_token(args)
    elif args.command == 'import':
        import_credentials(args)
    elif args.command == 'rotate':
        rotate_credentials(args)
