# Support

## Before asking

1. Read the [README](README.md) and the [documentation index](README.md#documentation-index).
2. Check the [wiki](https://github.com/paulmann/PHP-Form-Spam-Checker/wiki) for
   installation, configuration and deployment guides.
3. Search the [existing issues](https://github.com/paulmann/PHP-Form-Spam-Checker/issues),
   including closed ones, for the same symptom.
4. Reproduce on the latest release with `composer test` and `php -l` on the
   changed files before reporting a library defect.

## Where to ask

| Question | Channel |
|---|---|
| Bug in the library, a bridge or the WAF | [bug report](https://github.com/paulmann/PHP-Form-Spam-Checker/issues/new/choose) |
| Feature request or a check you would like | [feature request](https://github.com/paulmann/PHP-Form-Spam-Checker/issues/new/choose) |
| Documentation or wiki correction | pull request against `main` |
| Vulnerability or leaked secret | [SECURITY.md](SECURITY.md), never a public issue |
| Conduct concern | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), never a public issue |

## What a useful report contains

- the version (`composer show paulmann/php-form-spam-checker`) and the PHP version;
- the exact command or request and its exit code;
- the configuration section that matters, with secrets and keys removed;
- the `evidence` block of the verdict, with field values and client IP redacted;
- expected versus actual behaviour.

## What is out of scope

- Spam that is indistinguishable from legitimate text: the library is a filter,
  not an oracle.
- Host or HTTP-server compromise, and denial of service at the network layer.
- A deployment where someone who can edit `config/sites/<host>.php` disables the
  protections on purpose.

## Support terms

This is a volunteer-maintained open-source project with no service-level
agreement. Security reports are acknowledged within 72 hours; other issues are
answered when a maintainer can, usually during a release cycle.
