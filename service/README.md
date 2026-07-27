# DetLab Sigma conversion service

This optional service executes pySigma conversion outside the static browser application. The workbench stays compatible with GitHub Pages and calls this API only when an operator configures an absolute HTTP(S) origin.

## Security model

- explicit backend registry; request data cannot import Python modules or select arbitrary classes
- safe YAML parsing with maximum depth 20, maximum 20 aliases, and a 10,000-node post-load structure limit
- 256 KiB source limit
- five-second response timeout by default, enforced in a disposable worker process that is terminated on timeout
- conversion results are fully serialized in the worker before publication, so partial generated output is never returned
- narrow CORS allowlist from `DETLAB_CORS_ORIGINS`
- versioned converter provenance and canonical-source SHA-256 in each response
- no credentials accepted in the browser's API-origin field

The service does not provide authentication or global rate limiting. Bind it to localhost/LAN by default and place authentication, TLS, request-rate controls, and stricter body limits at the reverse proxy before any broader exposure.

## Local setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r service/requirements.txt
PYTHONPATH=service uvicorn detlab.api:app --host 127.0.0.1 --port 8000
```

Configure the workbench with `http://localhost:8000`, or set the build-time default:

```bash
NEXT_PUBLIC_DETLAB_CONVERSION_API=https://conversion.example.test npm run build
```

Set allowed browser origins on the service:

```bash
DETLAB_CORS_ORIGINS=https://detlab.example.test,http://localhost:3000 \
  PYTHONPATH=service uvicorn detlab.api:app --host 127.0.0.1 --port 8000
```

## API

- `GET /healthz`
- `GET /v1/backends`
- `POST /v1/convert`

Request:

```json
{
  "source": "title: ...",
  "target": "splunk"
}
```

Registered targets:

- `splunk`
- `elastic-eql`
- `elastic-esql`
- `microsoft-kusto`

## Tests

```bash
PYTHONPATH=service python -m unittest discover -s service/tests -p 'test_*.py' -v
cd web && npm test && npm run build
```

No endpoint in this service deploys a query to a SIEM or claims live validation.
