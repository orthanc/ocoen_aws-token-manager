What is this?
=============

This is a utility for working with AWS access tokens in a more secure way. The idea is to secure the static access tokens
issued to a user and make it easy to instead work with time limited session tokens. This enables 2 significant changes
that should reduce the risks associated with access token theft:

1. Because the static access tokens are accessed infrequently (only when obtaining new session tokens) they can be
   encrypted with a strong password without requiring a password entry for every operation.
2. Because session tokens can be obtained with an MFA token, IAM policies can be configured to require MFA for all
   operations without constantly prompting the user for an MFA token.

The workflow is similar to that of ssh-agent with an encrypted SSH keys. I.e. the user enters a password (and MFA token)
to enable access for a limited period of time, after which they have to re-authenticate.

Effectively this gives access token use similar protections to use of the interactive console with 2FA enabled.

Like the AWS CLI this utility supports assuming a role rather than just obtaining a session token, so can also be used
when a role is required, even if the tool to be called does not support assuming roles.

Security Warning
----------------

While all efforts have been made to follow security best practice, this project has not had an independent review.
Ensure that you've conducted appropriate security review for your environment.

Access Keys and passwords can be stored as either a KeePass database or an encrypted credentials file. KeePass
databases should be preferred for a secure environment as KeePass has substantially more review than the
ocoen_filesecrets library used for encrypted credentials.

Particularly note the security warning on [ocoen_filesecrets](https://github.com/orthanc/ocoen_filesecrets) which
is used to store the encrypted credentials. Then again, it can hardly be worse than the plain text that is being
replaced.

Any feedback on potential or actual security issues would be highly appreciated.

Installation
============

*Note: Python 3 is required*

This module is not published to PyPI (comment on [issue 1](https://github.com/orthanc/ocoen_aws-token-manager/issues/1) if
that would be useful to you), so it should be installed from this source repository using pip.

[install-requirements.txt](install-requirements.txt) contains the necessary required modules so AWS Token Manager can be
installed with the following command:

    $ pip install -r https://raw.githubusercontent.com/orthanc/ocoen_aws-token-manager/master/install-requirements.txt

If you want to isolate the install and it's dependencies from other python utilities I suggest using [pipenv](https://pipenv.readthedocs.io/en/latest/).
First, install pipenv, then:

Install AWS Token Manager using pipenv:

    $ mkdir aws-token-manager
    $ cd aws-token-manager
    $ wget https://raw.githubusercontent.com/orthanc/ocoen_aws-token-manager/master/install-requirements.txt
    $ PIPENV_VENV_IN_PROJECT=True PIPENV_SKIP_LOCK=True pipenv --three install -r install-requirements.txt

Link the `atm` command into `~/.local/bin` so it's on the path:

    $ ln -s "${PWD}/.venv/bin/atm" ~/.local/bin/

Examples And Usaage
===================

AWS Token Manager looks for static access keys in all the standard file locations specified for the [AWS CLI](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html).
Specifically:

* `~/.aws/credentials` or the location specified with the `AWS_SHARED_CREDENTIALS_FILE` environment variable
* `~/.aws/config` or the location specified with the `AWS_CONFIG_FILE` environment variable

The static access keys **cannot** be specified with environment variables as the environment variables are overridden by
obtaining a token.

The basic usage to obtain an session token is shown below. `atm` is the main command for aws token manager and called
with no sub-command obtains a session token. If the user has an MFA device associated with their account they will be
prompted for a code and the toke will be obtained with MFA.

    $ eval $(atm)
    MFA Token: 123456
    Token Obtained, valid til: 2019-01-05 03:36:24+13:00

Note the use of eval. The `atm` command prints a list of export environment variable statements that have to be run in the
current shell  If you run it without the eval you must copy the export statements and run them in your shell:

    $ atm
    Output is a terminal. Did you mean to run 'eval $(atm)' instead ?
    Do you really want to write the access tokens? (Y/N): y
    MFA Token: 123456
    export AWS_ACCESS_KEY_ID='...';
    export AWS_SECRET_ACCESS_KEY='...';
    export AWS_SESSION_TOKEN='...';
    Token Obtained, valid til: 2019-01-05 03:59:08+13:00

You can use the `-t` or `--life` option to control how many seconds the token is valid for (within the AWS limits on token
lifetime). E.g. to request a token that's only valid for 15 minutes:

    $ eval $(atm -t $((15 * 60)))
    MFA Token: 123456
    Token Obtained, valid til: 2019-01-05 03:36:24+13:00

It's also possible to specify a default lifetime of session tokes by specifying the `duration_seconds` option in the
shared configuration file (`~/.aws/config`). This option is described in the [AWS CLI Configuration Documentation](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#using-aws-iam-roles)
though the AWS Token Manager respects it for both obtaining session tokens and assuming roles.
Note that a command line`-t` or `--life` takes precedence over `duration_seconds`.

Using a KeePass Database
------------------------

In addition to the standard locations, AWS Token Manager looks for two KeePass databases to get static access keys from:
* `<SHARED_CREDENTIALS_FILE_LOCATION>-<PROFILE_NAME>.kdbx` - e.g. `~/.aws/credentials-default.kdbx`
* `<SHARED_CREDENTIALS_FILE_LOCATION>.kdbx` - e.g. `~/.aws/credentials.kdbx`

The first is to allow a different KeePass database for each profile. If you want to use a single KeePass database for
all profiles, use the second.

It's also possible to specify the location of the KeePass database for each profile in the shared configuration
file (`~/.aws/config`) using the `credentials_file` option. E.g.

```
[default]
credentials_file = ~/Dropbox/keepass.kdbx
```

AWS Token Manager expects a KeePass database to have a top level group named `AWS`. Within this group an entry
for each profile is expected with the name `<PROFILE_NAME> Access Key` (e.g. `default Access Key`). You can
change what entry is used by specifying the `access_key_path` option for the profile in the shared configuration
file. E.g. to use the entry `prod` in the group `Environment Keys`:

```
[default]
access_key_path = /Environment Keys/prod
```

The invocation of AWS Token Manager is unchanged when access keys are coming from a KeePass database. The only
difference is you'll now be prompted for an encryption password:

    $ eval $(atm)
    Password for credentials-default.kdbx:
    MFA Token: 123456
    Token Obtained, valid til: 2019-01-05 03:36:24+13:00

### Importing Existing Access Keys into a KeePass Database

AWS Token Manager cannot create a new KeePass database, you must give it an existing database. But it can update
an existing database with your existing access keys using the `import` command.

If `<SHARED_CREDENTIALS_FILE_LOCATION>-<PROFILE_NAME>.kdbx` exists, or a database has been specified with
`credentials_file` then running `atm import` will move your existing access keys from the shared credentials or
configuration file into the KeePass database.

The import command also gives you the option of removing the credentials from the existing unencrypted file and
rotating the access keys. While these are optional it's strongly recommended you take these actions as there's
minimal point encrypting the credentials if they also exist in an unencrypted file.

For example, to encrypt your credentials from the default profile of the shared credentials file (`~/.aws/credentials`):

```
$ ls ~/.aws
credentials
credentials-default.kdbx
$ atm import
Password for credentials-default.kdbx:
Import credentials from credentials into credentials-default.kdbx? (Y/N): y
Access key encrypted into credentials-default.kdbx
Do you want to remove the credentials from credentials (you may loose comments and formatting)? (Y/N): y
Access key removed from credentials
Do you want to rotate the access keys now? (Y/N): y
MFA Token: 123456
Access key rotated
```

To import the credentials from a different profile set the `AWS_PROFILE` environment variable or use the `--profile`
option.

The location of the KeePass database, and the entry to use can be specified using the `--target-file` and
`--target-access-key-path` arguments to the import command. If these are used you'll be given then option of
updating the shared configuration file to point at the same database / entry. E.g.

```
atm import --target-file ~/Dropbox/keepass.kdbx --target-access-key-path '/Environment Keys/prod'
Password for ~/Dropbox/keepass.kdbx:
Import credentials from credentials into keepass.kdbx? (Y/N): y
Access key encrypted into keepass.kdbx
Do you want to remove the credentials from credentials (you may loose comments and formatting)? (Y/N): y
Access key removed from credentials-default.kdbx
Do you want to update profile config to use the imported key (you may loose comments and formatting)? (Y/N): y
Do you want to rotate the access keys now? (Y/N): y
MFA Token: 123456
Access key rotated
```

After this sequence the shared configuration file contains:

```
[default]
credentials_file = ~/Dropbox/keepass.kdbx
access_key_path = /Environment Keys/prod
```

Working with Profiles
---------------------

AWS Token manager supports working with multiple profiles in a similar way to the [AWS CLI use of named profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html).
The profile to be used can be specified either with the `AWS_PROFILE` environment variable or using the `--profile`
argument to `atm`.

When using an encrypted credentials file remember that the profile name is part of the file name, but must also be
the section name. E.g. to use the `test` profile with an encrypted credentials file the following must be in
`~/.aws/credentials-test.enc`:

    [test]
    aws_access_key_id=...
    aws_secret_access_key=...

Then to obtain a session token indicate that the `test` profile should be used either by setting the `AWS_PROFILE`
environment variable or use the `--profile` argument as shown below:

    $ eval $(atm --profile test)
    Password for credentials-test.enc:
    MFA Token: 123456
    Token Obtained, valid til: 2019-01-05 03:36:24+13:00

Rotating Access Keys and Passwords
----------------------------------

The `atm rotate` command can be used to rotate the static access keys (i.e. generate a new access key and retire the
existing one). This is particularly handy when working with access keys stored in KeePass databases or encrypted
credentials files as it avoids the need to copy paste the new access keys.

To rotate the access keys simply run `atm rotate`:

    $ atm rotate
    Password for credentials-default.kdbx:
    MFA Token: 123456
    Access key rotated

The `atm rotate` command updates the credentials in whatever file it finds them in, so can also be used to rotate
credentials in the unencrypted shared credentials file or shared config file.

When a KeePass database is being used to store the access keys, you can rotate the IAM user password at the same
time by specifying the `--change-password` option. E.g.

```
$ atm rotate --change-password
Password for credentials-default.kdbx:
MFA Token: 123456
New Password for example-user (Leave blank to generate):
IAM password for example-user changed.
Access key rotated
```

The resulting password is stored in the KeePass database. By default it's stored in the `<PROFILE_NAME> Password`
(e.g. `default Password`) entry within the `AWS` group. This can be changed by specifying `password_path` in
the shared configuration file. E.g. to store the password in the `main` entry within the `Console Passwords` group:

```
[default]
password_path = /Console Passwords/main
```

If there is an existing password entry in the KeePass database that's used as the current password. The
`--prompt-password` argument can be used to diable this and prompt the user for the current password. This can
be useful if the password has been changed elsewhere and the KeePass database is out of date.


Assuming a Role
---------------

To assume a role configure a profile with a `role_arn` and `source_profile` in the [same was as for AWS CLI](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#using-aws-iam-roles).
For example:

```
# In ~/.aws/config
[profile crossaccount]
role_arn=arn:aws:iam:...
source_profile=development
```

The source profile credentials can be defined in the shared credentials or config file as normal, or in an encrypted
credentials file. Unlike the AWS CLI the `mfa_serial` option is ignored, rather if there is an MFA device associated
with the account the user will be prompted for an MFA token.

The `extenal_id`, `role_session_name` and `duration_sections` options are all supported and function the same way as
described in the [AWS CLI Configuration Documentation](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#using-aws-iam-roles).
Note that a command line`-t` or `--life` takes precedence over `duration_seconds`.

`mfa_serial` can also be specified but is usually unnecessary as AWS Token Manager will lookup the MFA device for
the current user.

Using Encrypted Credentials
---------------------------

As an alternative to using KeePass database the access keys can be stored in an Encrypted Credentials file. This
requires less setup than KeePass databases since AWS Token Manager can directy create these files. However this
format has had almost no security review so in a high security environment KeePass databases are recommended.

The encrypted credentials file for each profile is `<SHARED_CREDENTIALS_FILE_LOCATION>-<PROFILE_NAME>.enc`. e.g.
if you're using the default profile and credentials file location `~/.aws/credentials-default.enc`.

This file is encrypted with the [ocoen_filesecrets](https://github.com/orthanc/ocoen_filesecrets) module. This
file has the same format as the [AWS Shared Credentials File](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#the-shared-credentials-file)
but should only contain the section for the profile in use.

As with KeePass databases, the invocation of AWS Token Manager is unchanged:

    $ eval $(atm)
    Password for credentials-default.enc:
    MFA Token: 123456
    Token Obtained, valid til: 2019-01-05 03:36:24+13:00

### Encrypting the credentials

The encrypted credentials file must be encrypted with the [ocoen_filesecrets](https://github.com/orthanc/ocoen_filesecrets)
using the profile name (UTF-8 encoded) as the additional data.

The encrypted contents has the same format as the [AWS Shared Credentials File](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#the-shared-credentials-file)
but should only contain the section for the profile in use.

The easiest way to do this is with the `atm import` command. Import finds the existing AWS credentials and creates an
encrypted credentials file for you. The import command also gives you the option of removing the credentials from the
existing unencrypted file and rotating the access keys. While these are optional it's strongly recommended you take
these actions as there's minimal point encrypting the credentials if they also exist in an unencrypted file.

For example, to encrypt your credentials from the default profile of the shared credentials file (`~/.aws/credentials`):

    $ atm import
    Password for credentials-default.enc:
    Confirm Password for credentials-default.enc:
    Access key encrypted into credentials-default.enc
    Do you want to remove the credentials from credentials (you may loose comments and formatting)? (Y/N): y
    Access key removed from credentials
    Do you want to rotate the access keys now? (Y/N): y
    MFA Token: 123456
    Access key rotated

To import the credentials from a different profile set the `AWS_PROFILE` environment variable or use the `--profile`
option.

### Working with the encrypted credentials file

To directly work with the encrypted credentials file you can use the `fs-encrypt`, `fs-decrypt` and `fs-rekey` commands
from [ocoen_filesecrets](https://github.com/orthanc/ocoen_filesecrets).

To create the encrypted credential file use `fs-encrypt`. E.g. if you've already got the access keys in the shared
credentials file for the default profile, you can create the encrypted credential files by:

    $ fs-encrypt ~/.aws/credentials ~/.aws/credentials-default.enc -d default
    Password:
    Confirm Password:

To inspect the current credentials in the credentials file use `fs-decrypt`:

    $ fs-decrypt ~/.aws/credentials-default.enc - -d default | less
    Password:

To change the password on the encrypted credentials file use `fs-rekey`:

    $ fs-rekey ~/.aws/credentials-default.enc -d default
    Current Password:
    New Password:
    Confirm Password:

Required AWS Permissions
========================

It's strongly recommended users are allowed the following permissions **without requiring MFA**:

* iam:ListMFADevices

This is used to determine if the user has an MFA device.  If ListMFADevices permission cannot  be granted, users
must specify the MFA device using `mfa_serial` as described in the [AWS CLI Configuration Documentation](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#using-aws-iam-roles).

In order to support access key rotation the user must have IAM access to call the following IAM APIs for their own
user account. Though these can (and should) require MFA:

* iam:CreateAccessKey
* iam:DeleteAccessKey
* iam:ListAccessKeys

In order to support changing the IAM user password the user must have IAM access to call the following IAM APIs for
their own user account. Though these can (and should) require MFA:

* iam:ChangePassword

It's recommended that the below IAM policy be applied to all users who are expected to use AWS Token Manager. This will
grant the above permissions and require MFA for all operations other than ListMFADevices:

```JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListingMFADevices",
      "Effect": "Allow",
      "Action": [
        "iam:ListMFADevices",
      ],
      "Resource": "arn:aws:iam::AWS-ACCOUNT-ID:user/${aws:username}"
    },
    {
      "Sid": "DenyIfNoMfa",
      "Effect": "Deny",
      "NotAction": [
        "iam:ListMFADevices",
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    },
    {
      "Sid": "AllowAccessKeyRotation",
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys"
      ],
      "Resource": "arn:aws:iam::AWS-ACCOUNT-ID:user/${aws:username}"
    },
    {
      "Sid": "AllowPasswordChange",
      "Effect": "Allow",
      "Action": [
        "iam:ChangePassword"
      ],
      "Resource": "arn:aws:iam::AWS-ACCOUNT-ID:user/${aws:username}"
    }
  ]
}
```

Why is this better than aws-cli?
================================

The AWS CLI does support similar operations, namely:

* [Support for Assuming Roles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
* [sts get-session-token](https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html)
* [sts assume-role](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)

The built in assume role support targets almost the same use case as this, obtaining temporary security credentials,
optionally with MFA, in order to perform the actual work. However it has several limitations that I find frustrating:

Firstly, support for this has to be built into every client, not all clients support it, and those that do have differences
in the way they support it. E.g. boto2 does not have support for this, so many ansible AWS modules can't currently take
advantage of it. Boto3 does support assuming roles, but does not cache the credentials past the life of the process, so
the user is prompted for an MFA token each time they run a tool.

Secondly, while there is support for assuming a role with MFA, there is not support for obtaining a session token without
assuming a role. This means that it's impractical to require MFA on all access key use unless we want to require assuming
a role for all operations.

Finally, there's still no support for securing the access keys in any way, they sit in an unencrypted file in a well known
location. That just makes me sad.

The other two options are just raw wrappers around the underlying API calls, they're not setup to provide a workflow for
using the obtained session tokens.

The approach used in aws-token-manager solves these problems. Because the tokens are set as environment variables they can
be used by any client. This also means tokens obtained with a single MFA check can be used by multiple runs of tools that
need to access AWS services.

Because the static tokens are now needed less often they can be stored in an encrypted file.
