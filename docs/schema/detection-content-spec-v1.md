# DetLab Detection Content Specification v1

This repository implements the shared **DetLab Detection Content Specification v1** at:

- `schemas/detlab-detection-content-v1.schema.json`

The schema identifier is `https://schemas.detlab.dev/detection-content/v1.0.0/schema.json`.

## Contract boundary

The v1 contract is a portable, normalized interchange model. It does **not** replace the authored source format:

- Rich DetLab detection YAML remains canonical in `DetLab-DAC`.
- Sigma YAML remains canonical in `cybersecurity-playbook`.
- Adapters normalize either source into the same v1 shape.
- Splunk, Elastic, Kusto, and other target queries are derived artifacts, never competing authored sources.

The existing DetLab authored schema (`schema_version: 2.0.0`) can therefore evolve without changing the stable cross-repository v1 interchange contract.

## Required normalized fields

- identity: `spec_version`, `kind`, `id`, `title`, `description`
- lifecycle: `status`, `severity`, `authors`
- behavior: `platforms`, `attack`, `logsource`, `logic`
- canonical source provenance: `source.format`, `source.path`, `source.sha256`, `source.canonical`

`logic.body` contains selections. `logic.condition` remains explicit so consumers do not need format-specific condition discovery.

## Generated artifact provenance

Every generated artifact records:

- target and query language
- rendered content and its SHA-256
- canonical source SHA-256
- contract version
- converter package name and version

An artifact is stale when its recorded source hash or contract version no longer matches the normalized canonical source.

## Repository adapter

`service/detlab/contract.py` normalizes rich DetLab YAML and provides provenance/staleness helpers.

Tests:

```bash
PYTHONPATH=service python3 -m unittest discover -s service/tests -p 'test_*.py' -v
```
