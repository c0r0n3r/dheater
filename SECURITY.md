# Security Policy

D(HE)ater is a proof-of-concept tool that demonstrates the D(HE)at attack
([CVE-2002-20001](https://nvd.nist.gov/vuln/detail/CVE-2002-20001)). This policy
covers vulnerabilities **in D(HE)ater itself** — not the protocol weakness it
demonstrates, which is documented on the [official project site](https://dheatattack.com/dheater).

## Supported Versions

Security fixes are provided for the latest released version only. Please reproduce
any issue against the most recent release on
[PyPI](https://pypi.org/project/dheater/) before reporting it.

| Version | Supported |
| ------- | --------- |
| 0.4.x   | ✅        |
| < 0.4   | ❌        |

## Reporting a Vulnerability

Report security issues **privately** — do not open a public issue for an
undisclosed vulnerability.

- Email: coroner@pfeifferszilard.hu
- Alternatively, open a [confidential issue on GitLab](https://gitlab.com/dheatattack/dheater/-/issues/new)
  (tick *This issue is confidential*) or a
  [private security advisory on GitHub](https://github.com/c0r0n3r/dheater/security/advisories/new).

Please include the affected version, the platform and Python version, steps to
reproduce, and the impact. You can expect an acknowledgement within a few days.
Once a fix is available, the vulnerability will be disclosed together with the
release that addresses it.

## Responsible Use

D(HE)ater performs a real denial-of-service attack. Use it only against systems
you own or are explicitly authorized to test. Unauthorized use may be illegal and
will disrupt the targeted service. See the disclaimer in the
[README](README.md#disclaimer) for details.
