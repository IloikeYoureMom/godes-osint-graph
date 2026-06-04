# Godes OSINT Graph

> **Intelligence Link Analysis Platform** — Visualize connections between people, emails, phones, social media accounts, domains, and crypto wallets in an interactive force-directed graph. Built-in OSINT enrichment engine automatically discovers intelligence about your entities.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-00FF00?style=for-the-badge)]()
[![Graph](https://img.shields.io/badge/Graph-vis--network-3B82F6?style=for-the-badge)]()
[![OSINT](https://img.shields.io/badge/OSINT-Enriched-FF6B6B?style=for-the-badge)]()

---

##  **Live Demo Output**

```
╔══════════════════════════════════════════════════╗
║       Godes OSINT Graph is running            ║
║    Open http://127.0.0.1:5000 in browser         ║
╚══════════════════════════════════════════════════╝

┌─ Sidebar ──────────────────────────────────────┐
│  Godes OSINT Graph                           │
│     Intelligence Link Analysis                  │
│                                                 │
│  [＋ Add] [ Connect] [ Bulk Import]         │
│  [ Bulk Enrich] [ Export]                   │
│                                                 │
│  ┌─────────────────────────────────────┐        │
│  │  Search entities...            │        │
│  └─────────────────────────────────────┘        │
│  ┌─────────────────────────────────────┐        │
│  │ All Types                    ▼      │        │
│  └─────────────────────────────────────┘        │
│                                                 │
│  5 entities · 8 connections                     │
│                                                 │
│  ┌─────────────────────────────────────┐        │
│  │  user@example.com                │        │
│  │ email · breached · israeli         │  3 conn│
│  ├─────────────────────────────────────┤        │
│  │  054-1234567                     │        │
│  │ phone_number · mobile · partner    │  2 conn│
│  ├─────────────────────────────────────┤        │
│  │  johndoe                          │        │
│  │ username                           │  1 conn│
│  └─────────────────────────────────────┘        │
└─────────────────────────────────────────────────┘

┌─ Detail Panel ─────────────────────────────────┐
│  user@example.com                               │
│                                                 │
│  [EMAIL]                                         │
│                                                 │
│  ── OSINT Enrichment ──                         │
│  [Status]  Valid format                       │
│  [Domain] example.com                           │
│  [Provider] Google Workspace                    │
│  [MX Servers] alt1.gmail-smtp-in...             │
│  [Breach Check]  Found in breaches!           │
│                                                 │
│   Links / URLs (4)                            │
│  • Google Search                                │
│  • Hunter.io Email Verifier                     │
│  • HaveIBeenPwned                               │
│  • Pipl People Search                           │
│                                                 │
│   Connections (3)                             │
│  → johndoe [uses]                               │
│  → example.com [registered_at]                  │
│  ← 054-1234567 [associated_with]                │
│                                                 │
│  [ Enrich] [ Edit] [ Add Con] [ Del]   │
└─────────────────────────────────────────────────┘
```

---

##  **Features**

###  **Interactive Graph Visualization**
- **Force-directed graph** powered by vis-network with physics simulation
- **16 color-coded entity types** — people, emails, phones, domains, crypto, IPs, etc.
- Click to inspect, double-click to edit, drag to reposition
- Zoom, pan, fit-to-screen, and reset view controls
- Physics-based layout with forceAtlas2Based engine

###  **OSINT Enrichment Engine**
One-click intelligence discovery with automatic API integration:

| Entity Type | What It Discovers |
|------------|-------------------|
| ** Phone Numbers** | Israeli carrier detection (Pelephone, Cellcom, Partner, Golan), mobile vs landline, area codes, TrueCaller links |
| ** Emails** | MX record validation, Google/Microsoft/proton detection, HaveIBeenPwned breach check, pattern analysis (First.Last, etc.) |
| ** Domains/URLs** | DNS resolution, MX records, IP lookup, VirusTotal/WHOIS/crt.sh/Shodan links, .il detection |
| ** Usernames** | Pattern analysis (real name detection), search links for 17 platforms (TikTok, IG, GitHub, Reddit, etc.) |
| ** IP Addresses** | Public/private detection, reverse DNS, geolocation (ip-api.com), ISP, ASN, AbuseIPDB/Censys links |
| **₿ Crypto Wallets** | Wallet type detection (BTC, ETH, SOL, XMR, DOGE, TRX, ADA, LTC), blockchain explorer links |

###  **Bulk Operations**
- **Bulk Import** — Paste 50+ entities at once with auto-type detection
- **Bulk Enrich** — Enrich all unenriched entities in one click
- **Auto-Enrich** — Optional automatic enrichment on entity creation

###  **Evidence Collection**
- Upload images directly (PNG, JPG, GIF, WebP) with instant preview
- Attach labeled URLs with titles to any entity
- Organize with comma-separated tags and detailed notes

###  **Export & Analysis**
- Export complete graph as structured JSON
- Sort entities by connections (most linked) or creation date
- Filter by entity type, platform, or search term

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web interface |
| GET | `/api/entities` | List all entities (supports search, type, platform filters) |
| POST | `/api/entities` | Create entity |
| PUT | `/api/entities/<id>` | Update entity |
| DELETE | `/api/entities/<id>` | Delete entity |
| GET | `/api/relationships` | List all relationships |
| POST | `/api/relationships` | Create relationship |
| DELETE | `/api/relationships/<id>` | Delete relationship |
| GET | `/api/graph` | Full graph data (nodes + edges) |
| POST | `/api/enrich/<id>` | Enrich a single entity |
| POST | `/api/bulk-enrich` | Enrich all unenriched entities |
| POST | `/api/bulk-import` | Import multiple entities at once |
| GET | `/api/export` | Export complete graph as JSON |
| POST | `/api/upload` | Upload an image file |

---

##  **Data Storage**

All data is stored locally in an **SQLite database** (`osint_graph.db`). No external servers, no cloud dependencies — your intelligence stays on your machine. Full **JSON export** for backup and sharing.

---

##  **Project Structure**

```
godes-osint-graph/
├── app.py                  # Flask server & 18 REST API endpoints
├── enrichment.py           # OSINT enrichment engine (7 modules)
├── requirements.txt        # flask + dnspython
├── osint_graph.db          # SQLite (auto-created on first run)
├── static/
│   ├── css/
│   │   └── style.css       # 550+ lines dark theme, responsive
│   ├── js/
│   │   └── app.js          # 800+ lines vis-network, CRUD, modals
│   └── uploads/            # Uploaded evidence images
└── templates/
    └── index.html          # Single-page app with all modals
```

---

##  **Quick Start**

```bash
git clone https://github.com/godes/osint-graph.git
cd osint-graph
pip install -r requirements.txt
python app.py
# → Open http://127.0.0.1:5000
```

---

##  **Contributing**

PRs welcome! Ideas for new features:
- Add more enrichment modules (social media scraping, breach DBs)
- Timeline view for entity history
- Map view for geolocated IPs
- Graph import/export in different formats

---

##  **Disclaimer**

> For **authorized security research and educational purposes only.** Always obtain explicit permission before investigating targets.

---

##  **License**

[MIT License](LICENSE) — do what you want, just don't blame me.

---

<div align="center">

*Built with  by [godes](https://github.com/godes)*

</div>
