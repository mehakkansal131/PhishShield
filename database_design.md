# PhishShield Module 3: Database Design

## Database location and initialization

The application creates `instance\phishshield.db` automatically. The `instance` folder and tables are created by `simulation.database.initialize_database` when the Flask app starts. The SQLite database is local runtime state and is excluded from version control.

Initialization is safe to repeat. Schema version 1 is tracked with `PRAGMA user_version`. Before an existing unversioned database is upgraded, initialization creates and integrity-checks a complete SQLite backup in a temporary file, then publishes it without overwriting an existing path at `instance\phishshield.db.pre-v1.bak` (or beside a configured database path). If that backup path already exists, startup stops rather than trusting or overwriting it. Tables and indexes are created with `IF NOT EXISTS`; the default campaign is inserted only if absent; email metadata is synchronized from Module 1 JSON by email ID. Existing campaigns, participants, and events are not deleted or reset.

## Entity relationship overview

```text
campaigns 1 ───── * campaign_email_assignments * ───── 1 email_samples
    │                       │
    │                       └── assigned messages
    ├──────────── * events * ─────────────── 1 participants
    ├──────────── * participant_actions * ──┘
    └──────────── 0..1 campaign_pauses
```

Legacy events reference one campaign, one dataset email, and one synthetic participant. Participant lifecycle actions can reference an email when answering. Email body text and teaching explanations stay in the JSON dataset and are not copied into SQLite.

## Tables and constraints

### `campaigns`

| Column | Type | Constraints and purpose |
|---|---|---|
| `campaign_id` | TEXT | Primary key. The Module 2 default is `module-2-local`. |
| `campaign_name` | TEXT | Required display name. |
| `description` | TEXT | Required descriptive text, empty string allowed. |
| `status` | TEXT | `draft`, `active`, or `completed`. |
| `created_at` | TEXT | Required UTC ISO-8601 timestamp. |
| `started_at` | TEXT | Nullable until the campaign starts. |
| `completed_at` | TEXT | Nullable until completion. |

The existing local-training campaign starts as active. The service can create additional draft campaigns and move them to active, paused, or completed status. A pause is stored in `campaign_pauses`; the original campaign table constraint and existing records are preserved.

### `campaign_email_assignments`

| Column | Type | Constraints and purpose |
|---|---|---|
| `campaign_id` | TEXT | Foreign key to the campaign. |
| `email_id` | TEXT | Foreign key to a dataset email. |
| `assigned_at` | TEXT | UTC time the message was assigned. |

The campaign/email pair is the primary key. Assignment changes are limited to draft campaigns before activity begins. Existing default campaign messages are assigned idempotently at initialization.

### `campaign_pauses`

| Column | Type | Constraints and purpose |
|---|---|---|
| `campaign_id` | TEXT | Primary and foreign key to a campaign. |
| `paused_at` | TEXT | UTC time the active campaign was paused. |

A paused campaign is surfaced as `paused` by the store interface; resuming removes this pause row and retains the original `started_at`.

### `email_samples`

| Column | Type | Constraints and purpose |
|---|---|---|
| `email_id` | TEXT | Primary key matching the Module 1 dataset. |
| `email_type` | TEXT | `phishing` or `legitimate`. |
| `scenario` | TEXT | Dataset scenario title. |
| `subject` | TEXT | Dataset subject. |
| `sender_display_name` | TEXT | Dataset display name. |
| `sender_email` | TEXT | Fictional sender address from JSON. |
| `reply_to` | TEXT | Fictional reply destination from JSON. |
| `created_at` | TEXT | Time the metadata record was first seeded. |

The email body, trigger, indicators, feedback, and recommendation are intentionally not duplicated in this table.

### `participants`

| Column | Type | Constraints and purpose |
|---|---|---|
| `participant_id` | TEXT | Primary key; random synthetic browser-session identifier. |
| `display_name` | TEXT | Optional non-identifying label; currently `NULL`. |
| `created_at` | TEXT | UTC ISO-8601 timestamp of first observed action. |

No participant name, email, password, or other personal information is collected.

### `participant_actions`

| Column | Type | Constraints and purpose |
|---|---|---|
| `action_id` | TEXT | Random primary key. |
| `campaign_id` | TEXT | Foreign key to the campaign. |
| `participant_id` | TEXT | Foreign key to the pseudonymous participant. |
| `email_id` | TEXT | Nullable foreign key; required for answers. |
| `action_type` | TEXT | `joined`, `answered`, or `completed`. |
| `response` | TEXT | `phishing`, `legitimate`, or `clicked`; never message content. |
| `is_correct` | INTEGER | Nullable; classification correctness, or `NULL` for simulated-link choices. |
| `timestamp` | TEXT | Time of the action in UTC ISO-8601. |
| `action_key` | TEXT | Unique deterministic key for duplicate prevention. |

Answers are unique per participant, campaign and email. A participant must join before answering and must answer every assigned email before completion can be stored.

### `events`

| Column | Type | Constraints and purpose |
|---|---|---|
| `event_id` | TEXT | Primary key; random UUID hex string. |
| `campaign_id` | TEXT | Required foreign key to `campaigns`. |
| `email_id` | TEXT | Required foreign key to `email_samples`. |
| `participant_id` | TEXT | Required foreign key to `participants`. |
| `event_type` | TEXT | `displayed`, `clicked`, or `reported`. |
| `timestamp` | TEXT | Required timezone-aware UTC ISO-8601 event time. |
| `session_event_key` | TEXT | Unique SHA-256 idempotency key derived from campaign, sample, participant, and event type. |

`UNIQUE(campaign_id, email_id, participant_id, event_type)` prevents duplicate counts if a participant refreshes or repeats a particular action for the same sample and campaign. A distinct action (for example, both a display and report) remains a separate event.

## Indexes

- `idx_events_campaign_timestamp` supports campaign activity timelines.
- `idx_events_campaign` supports campaign filtering.
- `idx_events_email` supports per-sample analysis.
- `idx_events_participant` supports anonymous participant-level deduplication queries.
- `idx_events_type` supports action totals.
- `idx_events_timestamp` supports time-based summaries.
- `idx_participant_actions_campaign_time` supports campaign activity reporting.
- `idx_participant_actions_participant` supports participant progress lookups.
- `idx_participant_answer_once` prevents multiple answers for one campaign/message/participant.

## Event type compatibility

Legacy simulation route handlers use `open`, `click`, and `report`. `SQLiteEventStore` preserves that interface and maps it to database vocabulary:

| Existing route/service value | SQLite value |
|---|---|
| `open` | `displayed` |
| `click` | `clicked` |
| `report` | `reported` |

Database query results are translated back to the existing values for feedback pages and templates.

## Transactions and safety

Each operation opens a SQLite connection and enables `PRAGMA foreign_keys = ON` on that connection. Write operations use `BEGIN IMMEDIATE` and commit only after related participant/event changes succeed. SQLite constraints and idempotency keys protect against invalid references and duplicate actions. SQL values—including filters and identifiers—are passed as bound parameters.

The SQLite busy timeout is ten seconds. On a database error, the service raises an explicit `EventStoreError` rather than silently presenting a successful result.

## Statistics and future analytics

The event store exposes campaign creation and editing, assignment management, pause/resume/close transitions, participant joins and answers, event filtering, progress, and aggregate counts. Dashboard totals are calculated from stored campaigns, events, and participant actions. Click/report percentages use unique participants with an intentional display as the denominator; completion percentage uses completed participants divided by joined participants. A zero denominator yields 0%.

## Reset and backup

There is no automatic reset command. Do not delete the database as part of normal startup or testing. An existing unversioned database is backed up before the first schema-v1 migration. Back up `instance\phishshield.db` before manual maintenance. A separate development reset tool should only be added if the team explicitly needs it and should require a clearly deliberate invocation and warning.
