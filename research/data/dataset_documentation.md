# PhishShield Sample Email Dataset

## Purpose and safe-use limits

`sample_emails.json` contains exactly ten fictional records: five labelled `phishing` and five labelled `legitimate`. The examples are for offline classroom demonstrations and later detector testing. All email addresses use reserved example domains, and any URLs use `example.com` as inert placeholders. There are no attachments, credential collection forms, or real organization/person identities.

Do not send these examples to real recipients or change them into credential-harvesting or malware-delivery content. In an educational presentation, explain that the labels are ground-truth labels for this small teaching set, not a universal definition of how messages look.

## Record schema

Every JSON list item has exactly the following keys:

| Field | JSON type | Meaning |
|---|---|---|
| `email_id` | string | Unique stable identifier for a sample. |
| `email_type` | string | `phishing` or `legitimate`. |
| `scenario` | string | Short description of the fictional email context. |
| `subject` | string | Fictional subject line. |
| `sender_display_name` | string | Name displayed by an email client. |
| `sender_email` | string | Fictional sender address. |
| `reply_to` | string | Fictional reply destination; may equal the sender. |
| `email_body` | string | Fictional body text. |
| `psychological_trigger` | string | The teaching concept illustrated, or an explicit none/routine value. |
| `suspicious_indicators` | array of strings | Signals for discussion; empty for samples with no designed warning signal. |
| `expected_detection_reason` | string | Explanation of the expected classification and its limits. |
| `recommended_user_action` | string | Safe recommended response. |

The JSON is deliberately a flat array of objects so Python's standard `json` module can load it without extra packages. The dataset does not contain technical mail headers or actual SPF/DKIM/DMARC results; those require a genuine message and trusted receiver-side evidence.

## Loading the dataset from Python

From the project root, future modules can load the file using only the standard library:

```python
import json
from pathlib import Path

dataset_path = Path("research") / "data" / "sample_emails.json"
with dataset_path.open(encoding="utf-8") as dataset_file:
    email_samples = json.load(dataset_file)

for sample in email_samples:
    print(sample["email_id"], sample["email_type"], sample["subject"])
```

For code running from an installed package or a different working directory, resolve the data path from the module's own file location rather than assuming the current directory. Validate the structure before relying on fields in a later module.

## Validation

Run the validator from the project root on Windows:

```powershell
py -3 research\validate_dataset.py
```

Expected output:

```text
Validation passed: 10 samples (5 phishing, 5 legitimate).
All required fields, labels, IDs, and JSON structures are valid.
```

The validator checks JSON parsing, the top-level list and record objects, exact schema, non-empty string fields, string-list indicators, allowed labels, unique IDs, ten total samples, and the 5/5 class balance. It uses no third-party packages.
