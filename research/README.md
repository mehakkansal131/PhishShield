# PhishShield Module 1: Social Engineering Research

This folder contains the project's research and safe sample data. Module 1 is independent of Flask and SQLite and does not send messages or perform email detection.

## Contents

- `social_engineering_research.md` — concepts, psychological triggers, methods, and safety scope.
- `case_studies.md` — three documented incident/campaign summaries with source links.
- `detection_indicators.md` — detection signals, their verification needs, and limitations.
- `data/sample_emails.json` — ten fictional labelled samples in consistent JSON format.
- `data/dataset_documentation.md` — schema, safe-use notes, and loading guidance.
- `validate_dataset.py` — standard-library dataset validation script.

## Windows validation

Install Python 3 if it is not already available, then open PowerShell in the project root and run:

```powershell
py -3 research\validate_dataset.py
```

No dependencies need to be installed. See [dataset_documentation.md](./data/dataset_documentation.md) for the expected output and Python loading example.

## Research and references

The case studies link to public CISA and US Department of Justice sources. Read [case_studies.md](./case_studies.md) alongside those primary sources; the report marks project analysis separately from documented facts and does not infer a victim's exact motivations.

## Scope boundary

This module is for authorized educational study and offline testing. Keep all messages fictional, retain the reserved `example.com` placeholders, and do not contact real recipients. Simulation campaigns, tracking, Flask routes, SQLite storage, and a detection engine are outside Module 1.
