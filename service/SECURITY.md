# Service dependency security

## DiskCache advisory (`PYSEC-2026-2447`)

`pySigma==1.4.0` declares `diskcache==5.6.3` as a dependency, although pySigma's
runtime code does not import it and DetLab does not create or read a DiskCache.
The advisory requires both attacker write access to a cache directory and a
subsequent application read that invokes pickle deserialization. DetLab has no
such cache path, so the vulnerable operation is unreachable.

The service's dependency audit ignores only `PYSEC-2026-2447` and must fail for
all other findings. `service/tests/test_dependency_security.py` also starts the
service with imports of `diskcache` blocked, proving the API and converter
registry do not depend on it. Do not add DiskCache use unless it uses a
non-pickle serializer, a service-private non-attacker-writable directory, and a
new security review removes this exception or updates its rationale.

Run the policy-enforcing audit with:

```bash
python3 -m pip install pip-audit
./service/audit-dependencies.sh
```
