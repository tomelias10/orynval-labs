# Contributing to Orynval Labs

Thanks for helping improve the scanners. The highest-value contributions are small, reproducible, and easy to verify.

## Good contributions

- a synthetic fixture for an MCP / agent config shape we do not handle yet
- a reproducible false positive or missed detection
- a safer or more precise remediation
- deterministic output / redaction improvements
- documentation that removes setup or interpretation friction

Please do **not** include real credentials, customer data, private repositories, or production configuration in an issue or pull request.

## Local checks

Requires Go 1.27.1+.

```sh
make check
make race
make demo
```

Before opening a pull request, keep `gofmt`, `go vet`, tests, the race detector, and the existing coverage gate green.

## Reporting detector accuracy

Use the detector-accuracy issue template and reduce the case to the smallest synthetic fixture that still reproduces the behavior. Say what was observed, what you expected, and which tool produced it.

## Pull requests

Keep PRs focused. Explain:

1. the security or usability problem,
2. the smallest reproducible example,
3. the behavior before and after,
4. tests that prove the change,
5. whether output or detection semantics changed.

Avoid adding network access, telemetry, command execution, nondeterministic clocks, or secret material. Those conflict with the project's core guarantees.

## Security vulnerabilities

Do not open a public issue containing exploit details for a vulnerability in Orynval Labs itself. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the repository's [Apache-2.0 license](LICENSE).
