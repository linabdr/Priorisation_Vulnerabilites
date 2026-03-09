# collecte des vulnérabilités IoT (NVD) de caméra ip, 
# les enrichit avec données d’exploitation (EPSS, KEV), 
# calcule un score de priorité 
# les stocke dans une base SQL (vulnerabilies.db).

import requests
import sqlite3
from datetime import datetime 
import time

# fonction de mapping CVE → type
def mapper_type_vulnerabilite(description, cve_id=""):
    """
    Associe une CVE à un type de vulnérabilité basé sur sa description
    Retourne un type parmi une liste prédéfinie pour caméras IP
    """
    description = description.lower()
    
    # Règles de mapping simples
    if any(kw in description for kw in ['authentication', 'bypass', 'login', 'credential', 'password']):
        return "auth_bypass"
    elif any(kw in description for kw in ['buffer overflow', 'memory corruption', 'heap', 'stack']):
        return "buffer_overflow"
    elif any(kw in description for kw in ['information disclosure', 'exposure', 'leak', 'sensitive']):
        return "info_disclosure"
    elif any(kw in description for kw in ['injection', 'command', 'sql']):
        return "injection"
    elif any(kw in description for kw in ['denial of service', 'dos', 'crash']):
        return "dos"
    elif any(kw in description for kw in ['default password', 'default credential', 'hardcoded']):
        return "default_creds"
    elif any(kw in description for kw in ['privilege escalation', 'privilege escalation']):
        return "priv_escalation"
    else:
        return "autre"
# ===== FIN DE LA FONCTION de mapping=====
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
nb_result = 100   # limiter pour test


# on créé la base SQL 'vulnerabilities'
conn = sqlite3.connect("vulnerabilities.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    severity TEXT,
    epss_score REAL,
    kev_status INTEGER,
    published_date TEXT,
    priority_score REAL,
    type_vulnerabilite TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS recommandations (
    type_vulnerabilite TEXT PRIMARY KEY,
    scenario_attaque TEXT,
    corrective TEXT,
    reduction_exposition TEXT,
    reduction_impact TEXT
)
""")

# Insérer les recommandations si la table est vide
cursor.execute("SELECT COUNT(*) FROM recommandations")
if cursor.fetchone()[0] == 0:
    recommandations = [
        ('auth_bypass',
         'Un attaquant contourne le mécanisme d\'authentification et prend le contrôle à distance de la caméra',
         'Mettre à jour le firmware vers la dernière version corrigeant le bypass',
         'Isoler la caméra sur un VLAN IoT, bloquer les ports d\'administration en WAN',
         'La caméra compromise ne peut pas accéder au reste du réseau (segmentation)'),
        
        ('buffer_overflow',
         'Un attaquant exécute du code arbitraire à distance via un débordement mémoire',
         'Appliquer le correctif du constructeur ou désactiver le service vulnérable',
         'Restreindre l\'accès réseau au service concerné, utiliser un pare-feu applicatif',
         'Surveiller les comportements anormaux et journaliser les accès'),
        
        ('info_disclosure',
         'Des informations sensibles (flux vidéo, identifiants) sont exposées',
         'Installer le patch de sécurité ou reconfigurer les paramètres de confidentialité',
         'Chiffrer tous les flux (HTTPS pour l\'interface, RTSPS pour la vidéo), utiliser un VPN',
         'Masquer automatiquement les visages dans les enregistrements si possible'),
        
        ('injection',
         'Un attaquant injecte des commandes malveillantes via des entrées non filtrées',
         'Nettoyer et valider toutes les entrées utilisateur, mettre à jour l\'application',
         'Désactiver les interfaces d\'administration exposées à Internet',
         'Appliquer le principe du moindre privilège sur les processus'),
        
        ('dos',
         'La caméra devient indisponible, empêchant la surveillance',
         'Appliquer les correctifs de stabilité, configurer le rate-limiting',
         'Mettre en place une redondance (caméra de secours), utiliser du load balancing',
         'Configurer des alertes de disponibilité pour réagir rapidement'),
        
        ('default_creds',
         'Des identifiants par défaut non modifiés permettent un accès non autorisé',
         'Forcer le changement des mots de passe à la première connexion',
         'Désactiver les comptes par défaut, utiliser l\'authentification centralisée (LDAP/RADIUS)',
         'Auditer régulièrement les comptes et leurs niveaux de privilège')
    ]
    
    cursor.executemany("""
        INSERT INTO recommandations
        (type_vulnerabilite, scenario_attaque, corrective, reduction_exposition, reduction_impact)
        VALUES (?, ?, ?, ?, ?)
    """, recommandations)
    
cursor.execute("DELETE FROM vulnerabilities")
conn.commit() # sauvegarde

# data kev
print("Downloading KEV catalog...")
kev_response = requests.get(KEV_URL) # permet de récupérer les données KEV (vulnérabilités exploitées)
kev_data = kev_response.json() 
kev_list = {item["cveID"] for item in kev_data["vulnerabilities"]} # permet de voir tous les id de vulnreabilites exploitees par les attaquants

# nvd data
print("Fetching CVEs from NVD...")

start_index = 0
results_per_page = 2000

while True:

    # param permet de ne selectionner que KEYWORD (ici : ip camera) et pour 20 pages
    params = {
        "keywordSearch": KEYWORD,
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }

    response = requests.get(NVD_URL, params=params)
    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        break

    for item in vulnerabilities: # pour chaque vulnérabilité

        # on extrait les infos NVD
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        
        # Détermination du type de vulnérabilité ici
        type_vuln = mapper_type_vulnerabilite(description, cve_id)
        
        metrics = item["cve"].get("metrics", {})
        cvss = 0.0
        severity = ""
        
        # extraction cvss
        try:
            # ici on prend la metriqueV3.1 car c'est lla plus recente, si elle n'existe pas alors on prend les versions plus anciennes
            if "cvssMetricV31" in metrics:
                metric = metrics["cvssMetricV31"][0]
                cvss = metric["cvssData"].get("baseScore", 0)
                severity = metric["cvssData"].get("baseSeverity", "")

            elif "cvssMetricV30" in metrics:
                metric = metrics["cvssMetricV30"][0]
                cvss = metric["cvssData"].get("baseScore", 0)
                severity = metric["cvssData"].get("baseSeverity", "")

            elif "cvssMetricV2" in metrics:
                metric = metrics["cvssMetricV2"][0]
                cvss = metric["cvssData"].get("baseScore", 0)
                severity = metric.get("baseSeverity", "")
                
        except Exception as e:
            print(e)
            cvss = 0.0

        published_date = item["cve"]["published"]

        epss_response = requests.get(f"{EPSS_URL}?cve={cve_id}")
        epss_json = epss_response.json()

        if epss_json["data"]:
            epss = float(epss_json["data"][0]["epss"])
        else:
            epss = 0.0

        if cve_id in kev_list :
            kev_status = True
        else : kev_status = False

        # Score de priorisation 

        # CVSS = gravité de l'impact --> sur 10 --> 
        # EPSS = probabilité d’exploitation --> mettre sur 10
        # KEV  = exploitation réelle confirmée --> mettre sur 10

        priority_score = (
            (cvss * 0.4) # 40% du poids car l'impact est à prioriser
            + (epss * 10 * 0.3) # 30% du poids car la probabilité d'exploitation n'est pas négligeable
            + (int(kev_status) * 10 * 0.3) # si l'exploitation est confirmée, le poids augmente de 30%
        )

        # stockage dans la bdd vulnerabilities.db

        cursor.execute("""
        INSERT OR REPLACE INTO vulnerabilities
        (cve_id, description, cvss_score, severity ,epss_score, kev_status, published_date, priority_score, type_vulnerabilite)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            description,
            cvss,
            severity,
            epss,
            kev_status,
            published_date,
            priority_score,
            type_vuln  # ← Nouveau champ ajouté
        ))

    start_index += results_per_page

    time.sleep(6)

    #print(f"Stored {cve_id} | Priority: {round(priority_score,2)}")

print("Generate index for vulnerabilities table")
# Optimisation en créant des index sur les colonnes
cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_cvss_score ON vulnerabilities(cvss_score);
""")
cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);
""")
cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_kev_status ON vulnerabilities(kev_status);
""")
cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_published_date ON vulnerabilities(published_date);
""")
cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_priority_score ON vulnerabilities(priority_score);
""")
cursor.execute("""
CREATE INDEX IF NOT EXISTS idx_cve_id ON vulnerabilities(cve_id);
""")

# Pour l'optimisation de la recherche => possibilité de crée une table fts5 (full text search)

conn.commit()
conn.close()

print("Collection completed successfully.")
