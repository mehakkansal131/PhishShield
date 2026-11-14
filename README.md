# PhishShield — Modules 1–6

PhishShield is a locally running cybersecurity education application. Module 1 supplies fictional, labelled samples; Module 2 presents safe simulation actions; Module 3 persists campaign metadata and anonymous interaction events in SQLite; Module 4 summarizes those records for an instructor; Module 5 provides explainable local email analysis; and Module 6 integrates and tests the workflow.

## Safety and scope

- The development server binds only to `127.0.0.1`.
- The app does not send email or contact real recipients.
- The displayed sample content is loaded from the Module 1 dataset and rendered as escaped text.
- Sample URLs are shown as plain text; the training action buttons submit to local PhishShield routes. The app does not accept a destination URL from the browser.
- Participant simulations never request or store passwords or sensitive information. Instructor authentication is separate from the training workflow.
- Anonymous browser-session identifiers are generated locally for event deduplication.
- Event data is stored in `instance/phishshield.db` and persists when the server stops.
- Campaign management, instructor research, dashboards, tracking, and CSV export require instructor login. There is no public instructor registration.
- There are no stealth, evasion, external delivery, or public deployment features.

Use the application only for classroom demonstrations and other authorized training.

## Architecture

Flask route handlers are registered in `simulation/__init__.py`. Dataset loading and participant-view filtering live in `simulation/campaign_service.py`. SQLite schema creation and safe seed-data handling live in `simulation/database.py`; persistent event and campaign operations live in `simulation/event_store.py`. Routes use the event-store interface rather than embedding SQL.

The application reuses the existing Module 1 dataset at `research/data/sample_emails.json`. The database stores email metadata but not the full email body, which remains in JSON as the content source. If that dataset is missing or invalid, the app logs the issue, shows a visible warning, and disables sample-dependent pages until the dataset is fixed.

## Module integration map

| Module | Existing files | Data flow |
|---|---|---|
| 1. Research | `research/*.md`, `research/data/sample_emails.json`, `research/validate_dataset.py` | Research pages serve a fixed allowlist of local Markdown references. The shared dataset is loaded by the campaign service and detection engine. |
| 2. Simulation | `simulation/campaign_service.py`, `simulation/__init__.py`, `templates/participant_*.html` | Participants join a campaign, receive assigned messages in order, submit decisions, and see feedback without labels on the message page. |
| 3. Tracking/database | `simulation/database.py`, `simulation/event_store.py`, `database_design.md`, `instance/phishshield.db` | SQLite persists campaigns, assignments, pause state, participant actions, and idempotent simulation events; email content remains in JSON. |
| 4. Dashboard | `simulation/analytics.py`, `templates/dashboard.html`, `static/js/dashboard.js`, `static/css/style.css` | Read-only analytics queries the SQLite store and supplies chart/table data to the dashboard. |
| 5. Detection | `detection/*.py`, `templates/detection.html` | A library email or manually entered message is analyzed by the existing `PhishingDetector`; results are not stored as campaign events. |
| 6. Integration/testing | `app.py`, `templates/base.html`, `templates/research.html`, `templates/help.html`, `tests/*.py`, this README | `create_app()` wires the services and shared navigation; tests exercise service, persistence, route, and cross-module boundaries. |

### End-to-end workflow

An instructor reviews the email library, creates a campaign, assigns messages and activates it. Participants open its local invitation, join pseudonymously, review messages and submit classifications or a safe simulated-link action. The service persists each intentional action in SQLite, presents educational feedback, and records completion. The dashboard calculates campaign, response, and completion metrics from those records. Separately, Detection analyzes a library email or user-entered message and displays the actual Python rule results without changing campaign tracking.

Participant exercise pages omit classifications until a response is submitted. The research library is an instructor view and shows classifications and teaching notes; because the app has no authentication, it is not access-controlled and must remain local.

If the dataset is missing, malformed, empty, or contains an invalid record, Flask starts in a degraded state and displays a visible warning. Research, simulation, and sample-based detection then show empty states; invalid sample actions return 404. Correct the JSON with `research/validate_dataset.py` before using those modules. Database/dashboard services remain available.

## Directory structure

```text
PhishShield/
├── app.py
├── requirements.txt
├── README.md
├── database_design.md
├── simulation/
│   ├── analytics.py
│   ├── database.py
│   ├── event_store.py
│   └── ...
├── templates/
│   └── dashboard.html
├── static/js/dashboard.js
├── detection/
│   ├── email_parser.py
│   ├── rules.py
│   ├── scorer.py
│   ├── evaluator.py
│   └── cli.py
└── tests/
    ├── test_analytics.py
    └── test_detection.py
```

The existing `research/`, `instance/`, campaign templates, and other tests remain in place.

## Windows setup

### 1. Open a terminal in the project folder

Open PowerShell or Command Prompt, then change to the directory containing this README. For example:

```powershell
cd "C:\Users\mehak\OneDrive\Desktop\PhishShield"
```

Confirm that the project files are present:

```powershell
Get-ChildItem
```

### 2. Check Python

```powershell
py -3 --version
```

If Windows cannot find `py`, install Python 3 and enable the Python launcher during installation.

### 3. Create and activate a virtual environment

```powershell
py -3 -m venv .venv
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

The virtual environment keeps this project's Python packages separate from other projects.

### 4. Install Flask

```powershell
python -m pip install -r requirements.txt
```

### 5. Start the local app

Configure an instructor login in the current PowerShell session. Generate a strong signing key and a password hash; the password prompt does not echo the password:

```powershell
$env:PHISHSHIELD_ENV = "development"
$env:PHISHSHIELD_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:PHISHSHIELD_INSTRUCTOR_USERNAME = "your-instructor-username"
$env:PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH = (python -c "from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass()))")
```

Set `PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH` to the generated hash, not the password itself. These commands do not save credentials to project files. `PHISHSHIELD_ENV` accepts `development`, `testing`, or `production`; if it is unset, local development is assumed, but an unknown value stops startup. Use the hosting provider's secret environment-variable settings for deployment and set `PHISHSHIELD_ENV` to `production`. Production startup fails if any required value is missing, the secret key is shorter than 32 characters, or the complete password hash is malformed or unsupported. Werkzeug scrypt and PBKDF2 hashes are accepted.

```powershell
python app.py
```

The console shows the local URL. Open <http://127.0.0.1:5000> in a browser on the same laptop. The app intentionally binds to loopback only.

The database normally uses `instance\phishshield.db`. To run with a separate database (for example, while checking the app), set `PHISHSHIELD_DATABASE_PATH` before startup:

```powershell
$env:PHISHSHIELD_DATABASE_PATH = "$env:TEMP\phishshield-local-check.sqlite"
python app.py
```

Instructor sessions use a 30-minute lifetime. In production, the session cookie is marked `Secure`, `HttpOnly`, and `SameSite=Lax`; serve the site over HTTPS. Development mode may generate an ephemeral secret when none is set, but instructor login still requires configured username and password-hash values. Login permits five failed attempts per client address within 15 minutes; this in-process limit is per worker, so a multi-worker deployment should also configure rate limiting at the hosting edge.

Importing `app` for tests does not create the Flask application or initialize the default database. Tests use in-memory storage or a temporary SQLite file.

To use another local port if port 5000 is already occupied:

```powershell
$env:PHISHSHIELD_PORT = "5050"
python app.py
```

Then open <http://127.0.0.1:5050>. In Command Prompt, set the value with `set PHISHSHIELD_PORT=5050` before running the app.

Stop the server with `Ctrl+C` in the terminal.

## Pages and interaction flow

1. `/` — workspace overview with links to each module.
2. `/campaigns/manage` — create and edit campaigns, assign library emails, activate, pause, resume, or close a campaign.
3. `/join/<campaign_id>` — local participant invitation and join page for an active campaign.
4. `/exercise/<campaign_id>` — presents the next assigned message through an explicit POST action.
5. `/exercise/<campaign_id>/<email_id>` — read-only participant view; the expected classification is withheld.
6. `/exercise/<campaign_id>/<email_id>/respond` — CSRF-protected classification or safe simulated-link action.
7. `/exercise/<campaign_id>/<email_id>/feedback` — immediate, private educational explanation and next step.
8. `/exercise/<campaign_id>/complete` — completion summary after all assigned messages receive a response.
9. `/research` and `/research/email/<email_id>` — searchable instructor library, classifications, indicators, and project research documents.
10. `/dashboard` and `/dashboard/campaign/<campaign_id>` — SQLite-backed totals, response rates, campaign activity, participants, and comparisons.
11. `/dashboard/export.csv` — aggregate campaign report.
12. `/detection` — analyze a library email or manually entered message using the Python rules.
13. `/instructor` — instructor-only summary of legacy campaign activity.
14. `/help` — workflow, interpretation, ethics, and limitations.

State-changing forms use a session-bound CSRF token. Ordinary page loads and browser prefetches do not count as participant actions. Email presentation, answers, reports, link interactions, joins, and completion are stored through explicit POST requests and deduplicated by campaign, participant, and message. A random pseudonymous identifier is generated on join; the app does not collect names or email addresses. Simulated links remain internal and no email is delivered.

Instructor-only routes enforce authorization on the server, including direct URL and POST requests. Participants can use invitation and exercise routes without instructor privileges. Production deployment must set all three authentication environment variables and serve over HTTPS. For multi-worker deployments, configure an edge rate limit in addition to the per-worker application limit.

## Module 3 database design

The database is created automatically at `instance/phishshield.db`; the `instance` folder is created on startup. Python's built-in `sqlite3` library is used, so no ORM or extra database package is needed. See [database_design.md](./database_design.md) for all columns, constraints, indexes, mappings, and transaction behavior.

| Table | Stored data |
|---|---|
| `campaigns` | Campaign name, description, status, and created/started/completed UTC timestamps. A single clearly named active local-training campaign is seeded once. |
| `email_samples` | Module 1 sample ID, type, scenario, subject, sender display name/address, reply-to, and metadata creation time. The body and instructor explanations remain in the JSON file. |
| `participants` | Synthetic participant identifier and creation time; no name or email is collected. |
| `events` | Campaign, email, participant, event type, UTC timestamp, and unique idempotency key. |
| `campaign_email_assignments` | The training messages assigned to each campaign. |
| `campaign_pauses` | Pause state for existing campaigns without rebuilding the campaign table. |
| `participant_actions` | Join, answer, and completion events, including response correctness without storing message bodies. |

Database event types are `displayed`, `clicked`, and `reported`; participant lifecycle actions use a separate table so existing event records and constraints remain intact. Schema version 1 is tracked with `PRAGMA user_version` and applies additive `CREATE TABLE IF NOT EXISTS` changes. Existing database records are not deleted or rewritten. The default campaign retains access to the existing dataset, while newly created campaigns store explicit email assignments.

Foreign keys are enabled on every connection. Parameterized queries are used for values. Unique constraints and deterministic idempotency keys protect against repeated actions. Initialization is repeatable and never resets or deletes records. A pre-refinement archive is preserved outside the project at `PhishShield-pre-refinement-20261105.zip`; continue to back up `instance/phishshield.db` before manual maintenance.

The event store exposes campaign creation, updates, status changes, assignments, participant actions, progress, event summaries, and participant lists. Assignment changes are limited to draft campaigns before activity begins. Completed campaigns cannot be reopened.

## Module 4 dashboard analytics

The dashboard at `/dashboard` reads directly from SQLite using `simulation/analytics.py`. It includes total, active and completed campaigns; unique participants; email presentations; simulated clicks and reports; correct and incorrect classifications; completion rate; campaign comparisons; scenario analysis; recent activity; a 30-day event timeline; campaign participant detail; and aggregate CSV export. Campaign filters use the `campaign_id` query parameter; invalid campaign IDs return 404 on detail pages.

Click-through rate is **unique participants who clicked ÷ unique participants with an intentional display × 100**. Report rate uses unique participants who reported over the same denominator. Completion rate is **participants who completed ÷ participants who joined × 100**. A zero denominator yields 0%. Correct/incorrect totals include classification answers only; the simulated-link choice is not scored.

Charts are rendered with local SVG and vanilla JavaScript; there are no chart-library or external-network dependencies. Data tables remain available as accessible alternatives. The timeline parses stored UTC ISO-8601 timestamps, skips malformed entries, and displays a clear empty state if no valid events exist. CSV export contains aggregate campaign metrics and protects text fields against spreadsheet-formula interpretation.

Dashboard data are instructor-facing and protected by instructor login; simulated participants do not see these labels or analytics in their campaign views. Instructor credentials are configured outside the database, so this authentication change does not alter the SQLite schema or existing records.

## Module 5 phishing email detection

The standalone engine is in `detection/`:

- `email_parser.py` normalizes Module 1 records and safely parses raw text or local `.eml` files with Python's standard `email` package. HTML is reduced to text and link metadata; scripts/styles are ignored. Attachments are represented by names only, never opened.
- `rules.py` contains independent checks for sender identity conflict, Reply-To mismatch, URL patterns, urgency/threat language, sensitive-information requests, link-plus-context action requests, attachment filename metadata, and trusted authentication results.
- `scorer.py` combines each rule at most once and returns a structured score, verdict, per-rule explanations, sender/URL summary, and limitations.
- `evaluator.py` loads and evaluates the existing Module 1 labels with a confusion matrix and standard binary metrics.
- `cli.py` provides local command-line evaluation and sample inspection.

The `/detection` route calls the same `PhishingDetector` service for a selected library message or validated manual text and URL inputs. It does not store analysis history or create campaign events. Other code can import `PhishingDetector` and call `PhishingDetector().analyze(email_record)`; keep analysis results separate from participant event data.

### Detection scoring

Default rule weights are: sender/display-name conflict 15; Reply-To mismatch 18; URL risk 24; urgency/threat 14; sensitive-information request 22; link-plus-context request 25; suspicious attachment metadata 18; and trusted authentication failure 14. Only a detected rule contributes once, regardless of repeated matching text. The total is capped to 0–100.

Default thresholds: 0–24 = **Low / Likely Legitimate**; 25–54 = **Medium / Suspicious**; 55–100 = **High / Likely Phishing**. Evaluation treats both **Suspicious** and **Likely Phishing** as the positive (`phishing`) class to avoid counting cautious medium-risk cases as legitimate. This configurable heuristic score is **not a calibrated probability**.

Missing Reply-To or authentication evidence produces an unavailable rule result with zero score contribution. Parsing an `Authentication-Results` header does not prove that the header is trustworthy. Authentication contributes only when a caller explicitly supplies evidence with `trusted: true`, representing results verified by the receiving mail system. Its aggregate status is `verified` only when SPF, DKIM, and DMARC all pass; a trusted failure is marked `failed`; incomplete or untrusted evidence is `inconclusive`. Even passing authentication is not proof that the content is benign.

The URL checks identify limited textual patterns such as IP hosts, selected URL shorteners, visible-label/destination mismatch, embedded user information, punycode, and unusually complex hostnames. Reserved example domains are not flagged just because they appear. URLs are never fetched. Attachment rules inspect filenames/extensions only and do not determine file safety.

### Run the detector on Windows

The engine uses only the Python standard library and needs no new package installation. From PowerShell in the project root (with the project's virtual environment activated if desired):

```powershell
python -m detection.cli evaluate
python -m detection.cli sample PS-PH-001
python -m detection.cli eml "C:\classroom\sample.eml"
```

The sample command prints one JSON result. To use another dataset file:

```powershell
python -m detection.cli evaluate --dataset "C:\path\to\labelled-emails.json"
```

The reusable Python interface accepts a dataset-style dictionary, raw RFC email text, `.eml` bytes, or a local path ending in `.eml`:

```python
from detection import PhishingDetector
from detection.email_parser import parse_eml_file

detector = PhishingDetector()
result = detector.analyze(email_record)
eml_record = parse_eml_file(r"C:\classroom\sample.eml")
eml_result = detector.analyze(eml_record)
```

Input messages have a 5 MiB limit. Parsing is local, does not contact URLs, and does not execute or decode attachment content.

### Evaluation and tests

The evaluator maps `email_type == "phishing"` to the positive class and labels a prediction phishing when the detector verdict is `Suspicious` or `Likely Phishing`. It calculates accuracy, precision, recall, F1-score, false-positive IDs, and false-negative IDs without scikit-learn. If a dataset does not contain both classes, it reports why binary evaluation is unavailable.

Run evaluation and tests:

```powershell
python -m detection.cli evaluate
python -m unittest discover -s tests -v
```

The current dataset has only ten synthetic samples. Evaluation is a repeatable smoke test—not evidence of real-world performance. Rules are general heuristics and the examples were designed for education, so performance on this set may overstate generalization.

### Safe example output (format illustration only)

The following is an illustrative output shape, **not measured PhishShield evaluation data**:

```text
PhishShield detector evaluation
Samples: <count>
Confusion matrix (actual rows, predicted columns):
...
Accuracy:  <calculated value>
Precision: <calculated value>
Recall:    <calculated value>
F1-score:  <calculated value>
```

To see actual results for the current dataset, run the evaluation command above; do not copy illustrative placeholders into a project report.

## Testing on Windows

Install the requirements as described above, then run from the project root:

```powershell
python -m unittest discover -s tests -v
```

The tests cover page responses, dataset loading and validation, unknown scenarios, CSRF rejection, simulated actions, duplicate-event prevention, preview GET side-effect prevention, campaign creation and selection, import-safe app loading, isolated database paths, instructor totals, degraded operation with missing/malformed/empty datasets, SQLite schema initialization, idempotent seeding, persistence, event-type mapping, timestamps, filtering, foreign-key enforcement, campaign lifecycle operations, analytics denominators, event timelines, CSV export, dashboard routes, safe research-document routing, detection UI integration, separation of analysis from campaign events, email parsing, detection rules, scoring, and dataset evaluation. Tests use in-memory storage or temporary SQLite databases, not `instance\phishshield.db`. Dashboard charts use browser-native SVG and local JavaScript; Node.js is not needed to run the app or tests.

Expected result: all tests pass, ending with a summary similar to:

```text
Ran 68 tests in 0.XXXs

OK
```

The exact number of seconds varies by computer.

You can separately validate the Module 1 JSON:

```powershell
python research\validate_dataset.py
```

## Troubleshooting

- **`No module named flask`:** Activate `.venv` and run `py -3 -m pip install -r requirements.txt`.
- **`py` is not recognized:** Install Python 3 with the Windows Python launcher, or use `python` if it is on `PATH`.
- **Dataset unavailable warning:** Confirm `research\data\sample_emails.json` exists and run the Module 1 validator. The app deliberately starts with sample-dependent pages disabled until the dataset is corrected.
- **SQLite database locked:** Stop other copies of the local app that may be writing to the database, then retry. Connections use a short SQLite busy timeout.
- **Database tables appear missing:** Confirm the app is running from the project and check `instance\phishshield.db`; startup initializes missing tables without resetting stored data.
- **Invalid JSON or missing fields:** Run the Module 1 validator and restore the expected dataset schema; do not silently substitute another dataset.
- **Port is already in use:** Set `PHISHSHIELD_PORT` to a free port, then browse to that local port.
- **PowerShell activation is blocked:** Use Command Prompt activation, or use the venv interpreter directly: `.\.venv\Scripts\python.exe app.py`.

## Integration status

- **Module 3 — SQLite tracking:** Implemented in this version. SQLite persistence replaces in-memory storage by default; `InMemoryEventStore` remains only as a lightweight test adapter.
- **Module 4 — dashboard:** Implemented in this version. The dashboard reads aggregate data from SQLite and does not expose participant names or email addresses.
- **Module 5 — detection engine:** Implemented as a reusable service and connected to the instructor-facing `/detection` page. Do not conflate the teaching label with the detector's result.
- **Module 6 — integration and testing:** Shared navigation, research/help pages, dataset degraded-mode handling, route integration, workflow tests, and local-only instructions connect the modules. Continue reviewing false positives as the dataset grows.

The instructor and dashboard pages remain educational development pages without authentication; production access control and multi-user deployment are outside the current project scope.
