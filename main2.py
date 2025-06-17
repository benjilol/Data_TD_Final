import os
import json
import re
import pandas as pd
import requests

# === Chemins relatifs ===
BASE_DIR = "C:/Users/benji/OneDrive/Documents/GitHub/Data_TD_Final"
PATH_AVIS = os.path.join(BASE_DIR, "Avis")
PATH_ALERTES = os.path.join(BASE_DIR, "alertes")
PATH_MITRE = os.path.join(BASE_DIR, "mitre")
EPSS_API = "https://api.first.org/data/v1/epss?cve="

# === Fonctions ===

def extraire_info_anssi(fichier_path, type_bulletin):
    with open(fichier_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    id_anssi = data.get("id", "N/A")
    titre = data.get("title", "N/A")
    date = data.get("initial_release_date", "N/A")
    cve_refs = [cve.get("name") for cve in data.get("cves", [])]
    return id_anssi, titre, date, type_bulletin, cve_refs

def extraire_info_cve(cve_id):
    fichier_path = os.path.join(PATH_MITRE, f"{cve_id}.json")
    with open(fichier_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    description = data["containers"]["cna"]["descriptions"][0]["value"]
    
    try:
        metrics = data["containers"]["cna"]["metrics"][0]
        cvss = metrics.get("cvssV3_1", metrics.get("cvssV3_0", {}))
        score = cvss.get("baseScore", None)
        severity = cvss.get("baseSeverity", None)
    except:
        score = None
        severity = None

    cwe = "Non disponible"
    cwe_desc = "Non disponible"
    try:
        pt = data["containers"]["cna"]["problemTypes"]
        if pt and "descriptions" in pt[0]:
            cwe = pt[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = pt[0]["descriptions"][0].get("description", "Non disponible")
    except:
        pass

    produits = []
    try:
        for p in data["containers"]["cna"]["affected"]:
            vendor = p.get("vendor", "N/A")
            produit = p.get("product", "N/A")
            versions = [v["version"] for v in p.get("versions", []) if v.get("status") == "affected"]
            produits.append((vendor, produit, versions))
    except:
        pass

    return description, score, severity, cwe, cwe_desc, produits

def get_epss_score(cve_id):
    try:
        url = EPSS_API + cve_id
        response = requests.get(url)
        data = response.json()
        return float(data["data"][0]["epss"])
    except:
        return None

# === Construction du DataFrame ===
rows = []

# Traitement des alertes
for fichier in os.listdir(PATH_ALERTES):
    if fichier.endswith(".json"):
        path = os.path.join(PATH_ALERTES, fichier)
        id_anssi, titre, date, type_bulletin, cves = extraire_info_anssi(path, "Alerte")
        for cve_id in cves:
            mitre_path = os.path.join(PATH_MITRE, f"{cve_id}.json")
            if os.path.exists(mitre_path):
                desc, cvss, severity, cwe, cwe_desc, produits = extraire_info_cve(cve_id)
                epss = get_epss_score(cve_id)
                for vendor, produit, versions in produits:
                    rows.append({
                        "ID ANSSI": id_anssi,
                        "Titre": titre,
                        "Type": type_bulletin,
                        "Date": date,
                        "CVE": cve_id,
                        "Description": desc,
                        "CVSS": cvss,
                        "Base Severity": severity,
                        "CWE": cwe,
                        "CWE Description": cwe_desc,
                        "EPSS": epss,
                        "Éditeur": vendor,
                        "Produit": produit,
                        "Versions affectées": ", ".join(versions)
                    })

# Traitement des avis
for fichier in os.listdir(PATH_AVIS):
    if fichier.endswith(".json"):
        path = os.path.join(PATH_AVIS, fichier)
        id_anssi, titre, date, type_bulletin, cves = extraire_info_anssi(path, "Avis")
        for cve_id in cves:
            mitre_path = os.path.join(PATH_MITRE, f"{cve_id}.json")
            if os.path.exists(mitre_path):
                desc, cvss, severity, cwe, cwe_desc, produits = extraire_info_cve(cve_id)
                epss = get_epss_score(cve_id)
                for vendor, produit, versions in produits:
                    rows.append({
                        "ID ANSSI": id_anssi,
                        "Titre": titre,
                        "Type": type_bulletin,
                        "Date": date,
                        "CVE": cve_id,
                        "Description": desc,
                        "CVSS": cvss,
                        "Base Severity": severity,
                        "CWE": cwe,
                        "CWE Description": cwe_desc,
                        "EPSS": epss,
                        "Éditeur": vendor,
                        "Produit": produit,
                        "Versions affectées": ", ".join(versions)
                    })

# Sauvegarde
df = pd.DataFrame(rows)
df.to_csv(os.path.join(BASE_DIR, "donnees_consolidees.csv"), index=False)
print("Fichier donnees_consolidees.csv généré avec succès.")


print("Fichiers trouvés dans 'Avis/' :", os.listdir(PATH_AVIS)[:10])
print("Fichiers trouvés dans 'alertes/' :", os.listdir(PATH_ALERTES)[:10])
print("Fichiers trouvés dans 'mitre/' :", os.listdir(PATH_MITRE)[:10])