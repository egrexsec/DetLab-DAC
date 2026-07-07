# Security Policy

## Scope

DetLab-DAC is primarily a documentation and content-authoring repository with a web workbench. The most relevant security concerns are:
- accidental exposure of GitHub tokens used with the workbench
- unsafe save-path assumptions in repo-backed authoring flows
- dependency or build-chain issues in the web frontend
- publication of sensitive internal detection logic, tenant data, or private telemetry examples

## Reporting

Please avoid opening a public issue with sensitive reproduction details first.

If no dedicated private reporting channel exists, open a minimally detailed GitHub issue labeled `security` and do not include tokens, internal telemetry, or exploit instructions.

## Maintainer expectations

Before merging:
- do not commit GitHub tokens or screenshots containing them
- validate authored examples for sensitive environment details
- run `cd web && npm test && npm run build`
- keep save targets and repository defaults explicit
