# 🛠️ VHI Toolbox — Automatisation & Supervision (Virtuozzo Hybrid Infrastructure)

> Outils pour gérer un cloud **VHI/OpenStack**, déployer des VMs applicatives via **cloud-init** (WordPress / Odoo) et superviser l’infra avec **Prometheus + Grafana**.

---

## ✨ Sommaire
- [Objectifs](#-objectifs)
- [Aperçu du dépôt](#-aperçu-du-dépôt)
- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration (VHI/OpenStack)](#-configuration-vhiopenstack)
- [Utilisation — VHI Manager (CLI)](#-utilisation--vhi-manager-cli)
- [Utilisation — VHI Manager (WEB)](#-utilisation--vhi-manager-web)
- [cloud-init (WordPress & Odoo)](#-cloud-init-wordpress--odoo)
- [Supervision (Prometheus & Grafana)](#-supervision-prometheus--grafana)
- [Alertes CPU (70%/90% sur 5 min)](#-alertes-cpu-7090-sur-5-min)
- [Tests rapides](#-tests-rapides)
- [Sécurité](#-sécurité)
- [Roadmap](#-roadmap)
- [Contribuer](#-contribuer)
- [Licence](#-licence)

---

## 🎯 Objectifs
- **Piloter VHI** via un client **Python** (Keystone v3, Nova, Neutron, Cinder, Glance).
- **Déployer automatiquement** des VMs applicatives prêtes à l’emploi (cloud-init).
- **Superviser** CPU/RAM/Disk/Réseau + **alerting** (Grafana/Prometheus).

---

## 🧭 Aperçu du dépôt
```text
.
├─ cloud-init/
│  ├─ Odoo.py                  # Déploiement Odoo prêt à l’emploi
│  └─ Worldpress.py            # Déploiement WordPress prêt à l’emploi
│
├─ vhi-cli.py
│
├─ vhi-web.php
│
└─ README.md
```

---

## ✅ Fonctionnalités
**VHI Manager (CLI/TUI)**
- Auth **Keystone v3** (token) et découverte des endpoints.
- **Dashboard projet** : #VMs, vCPU/RAM utilisés, volumes (GB), Floating IPs.
- **Création de VM (wizard)** :
  - Nom, **Image (Glance)**, **Flavor** (pré-sélection *small*), **Réseau (Neutron)**.
  - **Security Groups**, **IP DHCP / IP fixe**, **IP spoof ON/OFF**.
  - **SSH keypair** (import `.pub` ou existante), **cloud-init** (user-data base64).
- **Manage VM** :
  - **START / REBOOT (SOFT/HARD) / SHUTDOWN**.
  - **Config VM** : vCPU, RAM, disque local, total volumes attachés, IP, SG, spoof.

**cloud-init**
- **WordPress** : LAMP + WP-CLI, site FR auto, permaliens, rewrite, droits.
- **Odoo** : Postgres, venv Python, `requirements`, service `systemd`.

**Supervision**
- **Prometheus** scrappe `prometheus-node-exporter` (`:9100`) sur les VMs.
- **Grafana** : datasource Prometheus + dashboard **Node Exporter Full (ID 1860)**.
- **Alertes CPU** : Warning ≥ 70 % / 5 min, Critical ≥ 90 % / 5 min.

---

## 🔧 Prérequis
- Python **3.11+**
- Accès API **VHI/OpenStack** (Keystone v3)
- Ubuntu 24.04 LTS conseillé (supervision & nodes)
- Ouvertures réseau : `9090` (Prometheus), `3000` (Grafana), `9100` (node_exporter)

---

## 📦 Installation
```bash
git clone https://github.com/<org>/<repo>.git
cd <repo>

# environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# Dépendances
pip install -r examples/requirements.txt
```
---

## ⚙️ Configuration (VHI/OpenStack)
Préférez **variables d’environnement** :

```bash
export OS_AUTH_URL="https://<vhi-panel>:5000/v3"
export OS_USERNAME="evan"
export OS_PASSWORD="********"
export OS_USER_DOMAIN_NAME="LyceeJulesFil"
export OS_PROJECT_DOMAIN_NAME="LyceeJulesFil"
export OS_PROJECT_NAME="Evan"
```
---

## 🖥️ Utilisation — VHI Manager (CLI)
```bash
python vhi_manager/main.py
```

- **Dashboard** : stats projet, quotas, IP flottantes.
- **Créer une VM** : wizard interactif (image, flavor, réseau, SG, IP, SSH, user-data).
- **Gérer une VM** : start/stop/reboot + configuration détaillée.
  
  <img width="1072" height="706" alt="image" src="https://github.com/user-attachments/assets/91ad3409-8d02-42d2-a645-16e9049ef016" />

---

## 🖥️ Utilisation — VHI Manager (WEB)

Interface web servie derrière **WampServer (Apache)**, avec un backend js API.

- **Dashboard** : stats projet, quotas, IP flottantes.
- **Créer une VM** : wizard interactif (image, flavor, réseau, SG, IP, SSH, user-data).
- **Gérer une VM** : start/stop/reboot/vnc/snapshot + configuration détaillée.
- **Gérer nos NETWORK** : création/edit/suppression + configuration détaillée.
- **Gérer nos IP FLOAT** : allocation/libération.

  <img width="1918" height="863" alt="image" src="https://github.com/user-attachments/assets/8355fdea-9c3f-406e-99e0-4a40bac127be" />

## ☁️ cloud-init (WordPress & Odoo)

Placez vos fichiers dans `cloud-init/` (voir `wordpress.yml`, `odoo.yml`).  
Dans VHI, au moment de créer la VM depuis un template cloud-init ready, **collez le YAML** (`#cloud-config`) ou **importez le fichier**.

**Extrait `cloud-init/wordpress.yml`**
```yaml
#cloud-config
packages:
  - apache2
  - mariadb-server
  - php
  - php-mysql
runcmd:
  - apt-get update
  - systemctl enable --now apache2 mariadb
  - curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
  - php wp-cli.phar --info
```

---

## 📊 Supervision (Prometheus & Grafana)

### Sur chaque VM à superviser
```bash
sudo apt update
sudo apt install -y prometheus-node-exporter
sudo systemctl enable --now prometheus-node-exporter
# UFW (si actif) :
sudo ufw allow 9100/tcp
```

### Sur la VM supervision (Prometheus)
`/etc/prometheus/prometheus.yml` (exemple) :
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets:
          - '10.0.0.11:9100'
          - '10.0.0.12:9100'
          - '10.0.0.13:9100'
```

Reload :
```bash
sudo systemctl reload prometheus
```
Vérification : `http://<IP>:9090/targets` → targets **UP**.

  <img width="1447" height="227" alt="image" src="https://github.com/user-attachments/assets/860d3c52-25c9-4d7d-960c-9db85dedfb4a" />

### Grafana
- URL : `http://<IP>:3000` (login initial `admin`, forcer un nouveau mot de passe).
- **Data source** → Prometheus → URL : `http://localhost:9090` → *Save & Test*.
- **Dashboards** → *Import* → ID **1860** (*Node Exporter Full*) → *Import*.

  <img width="1591" height="757" alt="image" src="https://github.com/user-attachments/assets/dab062f1-ee44-4c2f-bcd3-761e728bb4d9" />

---

## 🚨 Alertes CPU (70%/90% sur 5 min)
`monitoring/rules_cpu.yml` :
```yaml
groups:
  - name: cpu.rules
    rules:
      - alert: CPU70Warn
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle",job="node"}[5m])) * 100) >= 70
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "CPU élevé (Warning) sur {{ $labels.instance }}"
          description: "≥ 70% depuis 5m ({{ $value | printf \"%.1f\" }}%)"

      - alert: CPU90Critical
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle",job="node"}[5m])) * 100) >= 90
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "CPU très élevé (Critical) sur {{ $labels.instance }}"
          description: "≥ 90% depuis 5m ({{ $value | printf \"%.1f\" }}%)"
```

**Notifications Grafana → Google Chat (webhook)**  
Alerting → *Contact points* → *New* → **Google Chat** (URL webhook).  
Alerting → *Notification policies* : `severity=warning|critical`.

  <img width="880" height="745" alt="image" src="https://github.com/user-attachments/assets/ff2a2a1e-15dd-4c0f-ac34-2e007dd07a4b" />

---

## 🧪 Tests rapides
**Monter la charge CPU (sur une VM)** :
```bash
sudo apt update && sudo apt install -y stress-ng
stress-ng --cpu 0 --cpu-load 100 --timeout 7m
```

**PromQL utiles (Grafana → Explore)** :
```promql
up{job="node"}
100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100
```

  <img width="1591" height="312" alt="image" src="https://github.com/user-attachments/assets/1155a307-bd52-4b1d-ad05-a169c16ba10a" />

---
