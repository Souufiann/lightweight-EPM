# 🛡️ LightWeight Endpoint Monitor

Une solution légère de détection et de réponse aux menaces (EDR) et de prévention des intrusions (IPS) conçue pour les environnements Windows, intégrant des concepts DevSecOps et une architecture conteneurisée.


## 🏗️ Architecture du Projet

Le projet suit une architecture **Client-Serveur** moderne :

1.  **Serveur Central (Dockerized) :** Le "cerveau" de l'application. Il gère la base de données, interroge les APIs de Threat Intelligence et héberge le dashboard d'observabilité.
2.  **Agent Endpoint (Windows Natif) :** Une sonde légère qui surveille les processus, vérifie les signatures numériques et applique les politiques de blocage (Firewall).


---

## ✨ Fonctionnalités Clés

* **Surveillance Réseau en Temps Réel :** Capture les connexions entrantes et sortantes liées aux processus locaux.
* **Vérification de Signature (Authenticode) :** Analyse via PowerShell pour ignorer les binaires de confiance (Microsoft, Google, etc.).
* **Intelligence sur les Menaces :** Intégration avec l'API **AbuseIPDB** pour catégoriser les menaces (Phishing, Malware, DDoS).
* **IPS Actif (Système de Prévention) :** Notifications Windows natives et blocage en un clic via le Pare-feu Windows.
* **Observabilité DevSecOps :** Graphiques linéaires en temps réel (Chart.js) visualisant le trafic sain vs suspect.
* **Conteneurisation :** Déploiement simplifié du backend via Docker et Docker Compose.

---

## 🚀 Installation et Déploiement

### 1. Déploiement du Serveur (Backend)
**Prérequis :** Docker & Docker Compose.

1.  Accédez au dossier `server/`.
2.  Créez un fichier `.env` :
    ```env
    ABUSEIPDB_API_KEY=votre_cle_api
    THREAT_THRESHOLD=20
    ```
3.  Lancez le service :
    ```bash
    docker-compose up --build -d
    ```
4.  Dashboard accessible sur : `http://localhost:5000`

### 2. Installation de l'Agent (Windows)
**Prérequis :** Python 3.10+, Droits Administrateur.

1.  Accédez au dossier `agent/`.
2.  Installez les dépendances :
    ```bash
    pip install psutil requests python-dotenv plyer
    ```
3.  Configurez l'URL du serveur dans le `.env` de l'agent :
    ```env
    SERVER_API_URL=http://<IP_DU_SERVEUR>:5000/api/evaluate
    ```
4.  Lancez l'agent (en tant qu'Administrateur) :
    ```bash
    python agent.py
    ```

---

## 📊 Dashboard d'Observabilité

Le dashboard web affiche une télémétrie en temps réel des événements réseau.

[Image of real-time network traffic line chart with safe and malicious lines]

* **Ligne Verte :** Connexions vérifiées ou sûres.
* **Ligne Rouge :** Tentatives de connexion vers des IPs blacklistées ou suspectes.

---

## 🛠️ Concepts DevOps Appliqués

* **Infrastructure as Code (IaC) :** Déploiement reproductible via Docker.
* **Observabilité :** Monitoring continu et visualisation des données de sécurité.
* **Sécurité à Gauche (Shift Left) :** Automatisation de la vérification des signatures dès l'exécution.
* **Configuration Externalisée :** Gestion via variables d'environnement (`.env`).

---

## ⚖️ Licence et Sécurité
Ce projet est destiné à un usage éducatif et de recherche en cybersécurité. L'automatisation du pare-feu comporte des risques ; utilisez-le avec prudence dans des environnements de production.
