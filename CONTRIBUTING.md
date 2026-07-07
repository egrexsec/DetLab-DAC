# Contributing to DetLab-DAC

Thanks for improving DetLab-DAC.

## Contribution priorities

High-value contributions usually improve one of these areas:
- canonical detection schema quality
- cross-platform detection clarity
- ATT&CK and telemetry documentation accuracy
- triage / validation guidance quality
- repo-backed authoring workflow reliability
- examples and pack publishing quality

## Good changes

- better detection documentation
- stronger Sigma / SPL / KQL / EQL / ES|QL parity
- clearer telemetry assumptions
- examples that show realistic analyst workflow
- tests for workbench config, output rendering, or save logic
- documentation that explains what DetLab is and is not

## Avoid

- turning the repo into a generic SOC platform
- adding unsupported marketing claims
- storing secrets in authored examples or screenshots
- mixing unrelated IR/lab/hunt content into detection-first flows without a strong reason

## Local workflow

### Web app

```bash
cd web
npm install
npm test
npm run build
```

### Repository helpers

```bash
make help
```

## Pull requests

Please include:
- what detection/documentation problem is being solved
- which repo area changed
- screenshots for UI changes
- any schema, fixture, or workflow assumptions introduced
