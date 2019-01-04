import os
# Importing readline makes input behave nicer (e.g. backspace works) so not actually unused
import readline  # NOQA

from argparse import ArgumentParser

import boto3

from ocoen.aws_token_manager import config
from ocoen.aws_token_manager.tty import if_not_tty, tty


@if_not_tty(prompt='Output is a terminal, do you really want to write the access tokens? (Y/N):')
def _export_token(token):
    print("export AWS_ACCESS_KEY_ID='" + token['AccessKeyId'] + "';")
    print("export AWS_SECRET_ACCESS_KEY='" + token['SecretAccessKey'] + "';")
    print("export AWS_SESSION_TOKEN='" + token['SessionToken'] + "';")


def _obtain_token(session, mfa_device, duration):
    args = {}
    if mfa_device:
        with tty():
            mfa_code = input('MFA Token> ')
        args['SerialNumber'] = mfa_device
        args['TokenCode'] = mfa_code
    if duration:
        args['DurationSeconds'] = duration

    return session.client('sts').get_session_token(**args)['Credentials']


def _get_mfa_device(session):
    mfa_devices = list(session.resource('iam').CurrentUser().mfa_devices.all())
    if mfa_devices:
        return mfa_devices[0].serial_number
    return None


def _get_base_credentials(profile_name):
    credential_files = [
        config.get_profile_config_file(profile_name),
        config.shared_config_file,
        config.shared_credentials_file,
    ]

    sections = ((f, f.get_profile_section(profile_name)) for f in credential_files)
    credentials = ((f, _extract_credentials(section)) for f, section in sections if section)
    return next(((creds, f) for f, creds in credentials if creds))


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


def main():
    parser = ArgumentParser()
    parser.add_argument('--profile', default=os.environ.get('AWS_PROFILE', 'default'),
                        help='The profile to work with. Defaults to the AWS_PROFILE environment variable or "default".')
    parser.add_argument('--life', '-t', type=int,
                        help='How long the token should be valid for, default is token type specific. Attempting to '
                             + 'specify a length longer than the max allowed results in an error.')
    # subparsers = parser.add_subparsers(title='subcommands')
    # request_parser = subparsers.add_parser('bob')
    args = parser.parse_args()

    session = boto3.Session(**_get_base_credentials(args.profile)[0])
    token = _obtain_token(session, _get_mfa_device(session), args.life)
    _export_token(token)
