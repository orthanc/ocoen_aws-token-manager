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

Currently this only issues session tokens for the same user that the static access tokens are for. A future enhancement
is to also support assuming a different role through the same workflow.

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

Using Encrypted Credentials
---------------------------

In addition to the standard locations, AWS Token Manager looks for static access keys in
`<SHARED_CREDENTIALS_FILE_LOCATION>-<PROFILE_NAME>.enc`. e.g. if you're using the default profile and credentials file
location `~/.aws/credentials-default.enc`.

Unlike the standard locations this file is expected to be encrypted with the [ocoen_filesecrets](https://github.com/orthanc/ocoen_filesecrets)
module. This file has the same format as the [AWS Shared Credentials File](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#the-shared-credentials-file)
but should only contain the section for the profile in use.

The invocation of AWS Token Manager is unchanged, the only difference is you'll now be prompted for an encryption password:

    $ eval $(atm)
    Password for credentials-default.enc:
    MFA Token: 123456
    Token Obtained, valid til: 2019-01-05 03:36:24+13:00

### Encrypting the credentials

The encrypted credentials file must be encrypted with the [ocoen_filesecrets](https://github.com/orthanc/ocoen_filesecrets)
using the profile name (UTF-8 encoded) as the additional data.

The encrypted contents has the same format as the [AWS Shared Credentials File](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#the-shared-credentials-file)
but should only contain the section for the profile in use.

To create the encrypted credential file use `fs-encrypt` from ocoen_filesecrets. E.g. if you've already got the access
keys in the shared credentials file for the default profile, you can create the encrypted credential files by:

    $ fs-encrypt ~/.aws/credentials ~/.aws/credentials-default.enc -d default
    Password:
    Confirm Password:

See the [ocoen_filesecrets documentation](https://github.com/orthanc/ocoen_filesecrets) for more options.

**TAKE NOTE OF THE SECURITY WARNING** in the ocoen_filesecrets docs.

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

Required AWS Permissions
========================

TODO

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
