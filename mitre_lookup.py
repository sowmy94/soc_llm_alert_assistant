import json

def load_mitre_mappings(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

def build_mitre_lookup(data):

    lookup = {}

    objects = data.get("objects", [])

    for obj in objects:

        if obj.get("type") == "attack-pattern":

            name = obj.get("name")

            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":

                    technique_id = ref.get("external_id")

                    lookup[technique_id] = name

    return lookup

