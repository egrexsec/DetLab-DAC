from detlab.packs import validate_pack_manifest


def test_validate_pack_manifest_success():
    manifest = {
        "name": "windows-core",
        "version": "1.0.0",
        "maintainer": "Mell0wx",
        "platforms": ["splunk", "elastic"],
    }

    errors = validate_pack_manifest(manifest)

    assert errors == []



def test_validate_pack_manifest_missing_fields():
    manifest = {
        "name": "windows-core",
    }

    errors = validate_pack_manifest(manifest)

    assert len(errors) > 0
