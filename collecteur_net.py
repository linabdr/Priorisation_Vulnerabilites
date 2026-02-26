# collecte des vulnérabilités IoT (NVD) de caméra ip, 
# les enrichit avec données d’exploitation (EPSS, KEV), 
# calcule un score de priorité 
# les stocke dans une base SQL (vulnerabilies.db).

import requests
import sqlite3
from datetime import datetime

# CONFIG

# base de vulnérabilité
# trouvé grace à https://nvd.nist.gov/developers/vulnerabilities
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# score de probabilité d'exploitation
# selon le site : Show EPSS scores for the first 100 CVEs
EPSS_URL = "https://api.first.org/data/v1/epss"

# catalogue des vulnérabilités exploitées
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEYWORD = "ip camera"   # famille IoT choisie
nb_result = 20   # limiter pour test


# on créé la base SQL 'vulnerabilities'
conn = sqlite3.connect("vulnerabilities.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    epss_score REAL,
    kev_status INTEGER,
    published_date TEXT,
    priority_score REAL
)
""")

cursor.execute("DELETE FROM vulnerabilities")
conn.commit() # sauvegarde

# data kev
print("Downloading KEV catalog...")
kev_response = requests.get(KEV_URL) # permet de récupérer les données KEV (vulnérabilités exploitées)
kev_data = kev_response.json() 
kev_list = {item["cveID"] for item in kev_data["vulnerabilities"]} # permet de voir tous les id de vulnreabilites exploitees par les attaquants

# nvd data
print("Fetching CVEs from NVD...")

# param permet de ne selectionner que KEYWORD (ici : ip camera) et pour 20 pages
params = {
    "keywordSearch": KEYWORD,
    "resultsPerPage": nb_result
}
response = requests.get(NVD_URL, params=params)
data = response.json()

vulnerabilities = data.get("vulnerabilities", []) # liste des CVE

for item in vulnerabilities: # pour chaque vulnérabilité

    # on extrait les infos NVD
    cve = item["cve"]
    cve_id = cve["id"]
    description = cve["descriptions"][0]["value"]
    metrics = item["cve"].get("metrics", {})

    # extraction cvss
    try:
        # ici on prend la metriqueV3.1 car c'est lla plus recente, si elle n'existe pas alors on prend les versions plus anciennes
        if "cvssMetricV31" in metrics:
            # print("ok cvssMetric31")
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        elif "cvssMetricV30" in metrics:
            # print("ok cvssMetric30")
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        elif "cvssMetricV2" in metrics:
            # print("ok cvssMetric2")
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        # print(cvss)

    except Exception as e:
        # print(e)
        cvss = 0.0

    published_date = item["cve"]["published"]

    epss_response = requests.get(f"{EPSS_URL}?cve={cve_id}")
    epss_json = epss_response.json()

    if epss_json["data"]:
        epss = float(epss_json["data"][0]["epss"])
    else:
        epss = 0.0

    if cve_id in kev_list :
        kev_status = 1
    else : kev_status = 0

    priority_score = (
        (cvss * 0.5) + (epss * 10 * 0.3) + (kev_status * 2)
    )

    # stockage dans la bdd vulnerabilities.db

    cursor.execute("""
    INSERT OR REPLACE INTO vulnerabilities
    (cve_id, description, cvss_score, epss_score, kev_status, published_date, priority_score)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        cve_id,
        description,
        cvss,
        epss,
        kev_status,
        published_date,
        priority_score
    ))

    print(f"Stored {cve_id} | Priority: {round(priority_score,2)}")


conn.commit()
conn.close()

print("Collection completed successfully.")