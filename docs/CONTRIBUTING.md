# Contributing to DetLab

Thanks for your interest in contributing to DetLab.

## Ways to contribute

- Add new detections
- Improve validation logic
- Add new report formats
- Improve documentation
- Add test coverage
- Suggest integrations for Sigma, Splunk, KQL, or cloud logs
- Add or refine DetLab knowledge-base entries under `knowledge/`

## Documentation rule

DetLab work is not complete until it is documented.

Use the DetLab framework in `docs/knowledge-management-framework.md` and start from the matching template exposed in `/detections/templates`.

Every contribution should aim to create one or more of the following:
- learning notes
- operational runbooks
- detection references
- threat hunting guides
- portfolio artifacts

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/detlab.git
cd detlab
python -m venv .venv
source .venv/bin/activate
pip install .[dev]
```

## Run checks

```bash
ruff check .
pytest
detlab validate detections
```

## Pull request guidelines

- Create focused pull requests
- Add or update tests for code changes
- Keep detection metadata complete
- Document new commands or schema fields
- Use clear commit messages
