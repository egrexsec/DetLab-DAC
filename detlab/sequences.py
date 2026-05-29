from detlab.models import Detection



def has_sequence(detection: Detection) -> bool:
    return hasattr(detection, "sequence") and detection.sequence is not None



def summarize_sequence(detection: Detection) -> dict:
    if not has_sequence(detection):
        return {
            "title": detection.title,
            "sequence": False,
        }

    sequence = detection.sequence

    return {
        "title": detection.title,
        "sequence": True,
        "within": sequence.get("within"),
        "events": len(sequence.get("events", [])),
    }



def build_eql_sequence(detection: Detection) -> str:
    if not has_sequence(detection):
        return ""

    sequence = detection.sequence
    within = sequence.get("within", "5m")

    eql_parts = [f"sequence with maxspan={within}"]

    for event in sequence.get("events", []):
        selections = event.get("selection", {})

        conditions = []

        for field, value in selections.items():
            normalized = field.split("|")[0].lower()

            if isinstance(value, list):
                joined = " or ".join([f'{normalized} == "{v}"' for v in value])
                conditions.append(f"({joined})")
            else:
                conditions.append(f'{normalized} == "{value}"')

        eql_parts.append(f"  [process where {' and '.join(conditions)}]")

    return "\n".join(eql_parts)
