# Verified open-source contributions

These links record accepted contributions by Tom Elias (`tomelias10`). They are evidence of individual contributions, not customer logos, product adoption, endorsements, or proof of compromise. Dates are UTC.

## Changes accepted by project maintainers

| Project | Accepted change | Date | Primary evidence |
| --- | --- | --- | --- |
| Datadog Android SDK | A maintainer agreed with a report about a mutable MCP package reference and removed the MCP configuration entry. | 2026-09-30 | [Report #3904](https://github.com/DataDog/dd-sdk-android/issues/3904), [maintainer's merged change #3928](https://github.com/DataDog/dd-sdk-android/pull/3928) |
| Builder.io agent-native | Pinned the shadcn MCP package in a community template to an exact version. | 2026-09-27 | [Merged contribution #5896](https://github.com/BuilderIO/agent-native/pull/5896) |
| agentic-awesome-skills | Added a static MCP dependency drift audit skill. | 2026-09-25 | [Merged contribution #1607](https://github.com/sickn33/agentic-awesome-skills/pull/1607) |

## Tool-list entries

| List | What was accepted | Date | Primary evidence |
| --- | --- | --- | --- |
| AlexMili/Awesome-MCP | mcp-drift tool entry. | 2026-10-03 | [Merged contribution #236](https://github.com/AlexMili/Awesome-MCP/pull/236) |
| abordage/awesome-mcp | MCP Drift Check entry. | 2026-09-25 | [Merged contribution #128](https://github.com/abordage/awesome-mcp/pull/128) |
| gmh5225/awesome-ai-security | MCP Drift Check entry. | 2026-09-27 | [Merged contribution #33](https://github.com/gmh5225/awesome-ai-security/pull/33) |
| scadastrangelove/awesome-ai-security-tools | WATCHLIST entry with explicit scope and GitHub Action caveats; not main-list placement. | 2026-09-27 | [Merged contribution and maintainer review #129](https://github.com/scadastrangelove/awesome-ai-security-tools/pull/129) |

The WATCHLIST maintainer specifically said they did not install or run MCP Drift Check. Their feedback on CI error handling and external sharing informed [a subsequent fix in MCP Drift Check #21](https://github.com/tomelias10/mcp-drift-check/pull/21); the fix does not imply a renewed endorsement or independent verification.

## What the tools establish

MCP Drift Check statically classifies package references. Orynval Labs' mcp-drift also inspects configured scope, launchers, inline credentials, endpoints, and differences from an approved configuration baseline. Neither runs discovered MCP servers. A mutable reference alone does not establish malicious code or compromise, and an exact direct version does not guarantee integrity or fully reproducible transitive dependencies.

Try [mcp-drift](../README.md#-quick-start), review the output, and send detector feedback as a synthetic example rather than exposing a private configuration.
