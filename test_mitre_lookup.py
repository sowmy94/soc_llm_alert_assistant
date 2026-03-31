from pathlib import Path
from mitre_lookup import build_mitre_lookup, load_mitre_mappings
from detect import detect_mitre_from_alert

def test_load_mitre_mappings():
    #data = load_mitre_mappings("enterprise-attack.json")

    '''objects = data.get("objects", [])
    techniques = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
    ]
    #for all objects in data get the technique name and technique id for each technique only if obj.get("type") == "attack-pattern" and print them
    for technique in techniques:
        technique_name = technique.get("name")
        technique_id = None
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
            
    print(f"Technique ID: {technique_id}, Technique Name: {technique_name}")'''

    file_path = "Data/enterprise-attack.json"

    data = load_mitre_mappings(file_path)
    lookup = build_mitre_lookup(data)

    print("Total techniques in lookup:", len(lookup))
    print("\nSample lookup entries:\n")

    for k, v in list(lookup.items())[:10]:
        print(k, "→", v)

    alert = "Attacker used VNC for remote access"
    result = detect_mitre_from_alert(alert, lookup)

    print("\nAlert:", alert)
    print("Detection Result:", result)

test_load_mitre_mappings()