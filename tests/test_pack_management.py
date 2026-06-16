from detlab.packs import determine_pack_health, validate_pack_manifest



def test_validate_pack_manifest_success():
    manifest = {
        "name": "windows-core",
        "version": "1.0.0",
        "maintainer": "Mell0wx",
        "description": "Windows coverage pack",
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
    assert any("description" in error for error in errors)



def test_determine_pack_health_marks_empty_valid_packs_as_seed():
    assert determine_pack_health(
        {
            "manifest_valid": True,
            "detections_valid": True,
            "detection_count": 0,
        }
    ) == "seed"



def test_determine_pack_health_marks_valid_nonempty_packs_as_healthy():
    assert determine_pack_health(
        {
            "manifest_valid": True,
            "detections_valid": True,
            "detection_count": 2,
        }
    ) == "healthy"



def test_determine_pack_health_marks_invalid_packs_for_attention():
    assert determine_pack_health(
        {
            "manifest_valid": False,
            "detections_valid": True,
            "detection_count": 2,
        }
    ) == "needs-attention"
