# Sentinel-8 — Essential Eight Compliance Mapper

THREAT_TO_E8 = {
    "Generic":        {"control": "#1 — Application Control",          "risk": "High"},
    "Exploits":       {"control": "#2 — Patch Applications",           "risk": "High"},
    "Fuzzer":         {"control": "#2 — Patch Applications",           "risk": "Medium"},
    "DoS":            {"control": "#8 — Regular Backups",              "risk": "High"},
    "Reconnaissance": {"control": "#5 — Restrict Admin Privileges",    "risk": "Medium"},
    "Analysis":       {"control": "#1 — Application Control",          "risk": "Medium"},
    "Backdoor":       {"control": "#1 — Application Control",          "risk": "High"},
    "Shellcode":      {"control": "#2 — Patch Applications",           "risk": "High"},
    "Worms":          {"control": "#1 — Application Control",          "risk": "High"},
    "Brute Force":    {"control": "#7 — Multi-Factor Authentication",  "risk": "High"},
    "Normal":         {"control": "None",                              "risk": "None"},
}

def map_threat(threat_type):
    result = THREAT_TO_E8.get(threat_type, {
        "control": "Unknown", "risk": "Medium"
    })
    return {
        "threat_type": threat_type,
        "e8_control":  result["control"],
        "risk_level":  result["risk"],
    }

if __name__ == "__main__":
    # Quick test
    tests = ["Exploits", "Backdoor", "Brute Force", "DoS", "Normal"]
    for t in tests:
        print(map_threat(t))