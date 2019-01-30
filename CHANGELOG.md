0.3.0
=====

* Support for specifying a MFA device in aws config using `mfa_serial` rather than discoveringa the MFA device
* Remove requirement for `iam:GetUser` permission to work with more constrained environments

0.2.0
=====

* Support for assuming the role defined by `role_arn` in the shared config file
* Support `duration_seconds` option in shared config file to default the token lifetime
* Export new `AWS_SESSION_EXPIRY` environment variable indicating when the token expires.

