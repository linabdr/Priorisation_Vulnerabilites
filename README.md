# Priorisation_Vulnerabilites
---

# Réalisé par
- **Lina Bader**
- **Maxime Bintein**
- **Oum el kheir Righi**

---

## Contexte et Objectif

Ce projet consiste à réaliser une plateforme web qui permet d'informer les utilisateurs sur les vulnérabilités pertinentes sur les caméras IP.
Les vulnérabilités sont récupérées automatiquement à partir des sources du NIST, FIRST et du CISA.

Ce projet s'inscrit dans le cours de Cybersécurité de l'IoT 8INF917. Il vise à renforcer la capacité à surveiller, comprendre et prioriser ces vulnérabilités afin de réduire les risques.

---

## Technologie

Les technologies utilisées pour le développement de ce projet sont:
- NextJS: Framework de React qui nous permet de faire une webapp full-stack rapidement. 
- Python: Utilisé pour récupérer les vulnérabilités via les APIs des différentes sources, ainsi que le traitement et le stockage dans un .db
- SQLite3: Utilisé pour stocker nos deux tables: "vulnerabilities" et "recommandations"
- Docker: Utilisé pour containeriser l'application, ce qui permet une meilleure portabilité, ainsi qu'une facilité d'installation
- Cron: Utilisé pour exéctuer toutes les heures le script Python de récupération des vulnérabilités

---

## Installation

### Prérequis
- Docker
- Navigateur

``` bash
git clone https://github.com/linabdr/Priorisation_Vulnerabilites.git
cd Priorisation_Vulnerabilites/
sudo docker compose up
```

---

## Utilisation

- Barre de recherche: Permet de chercher une CVE spécifique, ou alors un mot clé présent dans la description (ex: nom de la caméra IP)
- Divers filtres:
    - Possibilité de sélectionner une fourchette de score CVSS particulière
    - Possibilité de trier par: 
        - Score CVSS
        - Score EPPS
        - Score de priorité
        - Date de parution
    - Possibilité d'afficher seulement les failles qui sont exploitées en ce moment
    - Possibilité de sélectionner seulement les failles en fonction du type de vulnérabilités
    - Possibilité de sélectionner la sévérité des failles
- Chaque CVE est décrite par un son nom, une description, un score CVSS, un score EPPS, la date de parution, son score de priorité, le type de vulnérabilités, ainsi qu'une section avec les recommandations, avec à l'intérieur un scénario d'attaque, une proposition de corrective, de réduction de l'exposition, ainsi que de réduction de l'impact.

Le calcul pour le score de priorité est le suivant:  (cvss * 0.4)  + (epss * 10 * 0.3)  + (kev_status * 10 * 0.3).
