# PhishShield Module 1: Documented Case Studies

These summaries separate what the source reports from the project's interpretation. Dates are approximate when the activity spanned more than one year. Attribution is stated only as the cited government source states it. No case below is reproduced as an operational email template.

## 1. BeagleBoyz: job-themed spear-phishing against financial institutions

- **Approximate date:** 2018 through early 2020; CISA also reported renewed bank targeting beginning in February 2020.
- **Organization or context:** Financial institutions in multiple countries. The joint advisory describes a state-sponsored group known as BeagleBoyz, while many victim organizations are not named publicly.
- **Documented technique:** CISA reported spear-phishing and watering-hole activity as initial access methods, including job-application-themed phishing attacks aimed at financial institutions. The group's broader campaign sought fraudulent international transfers and ATM cash-outs.
- **Psychological/organizational factor (analysis):** A job application can appear relevant to staff who review recruiting or business correspondence. That is a plausible familiarity/role-based lure; the advisory documents the theme, not the motivation or response of every recipient.
- **Impact:** The advisory describes a global cyber-enabled bank robbery scheme and fraudulent transfer/ATM-cash-out activity. It does not provide a complete public list of victims or a single total attributable to the specific job-themed messages; this summary therefore does not assign a loss figure to those messages.
- **Lessons and controls:** Train staff to handle unexpected application files or links through established processes; use layered email and endpoint protections; limit privileges; monitor unusual payment workflows; require out-of-band verification and dual approval for transfers; and share indicators through trusted incident-response channels.
- **Source:** CISA, *FASTCash 2.0: North Korea's BeagleBoyz Robbing Banks* (AA20-239A), joint advisory: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a>

## 2. Celas Trade Pro: phishing that promoted a trojanized cryptocurrency application

- **Approximate date:** 2018 (the CISA/FBI advisory was published in 2021).
- **Organization or context:** An undisclosed victim company. The US government advisory describes a malicious cryptocurrency-trading application presented as Celas Trade Pro.
- **Documented technique:** A phishing email attributed in the advisory to a purported Celas LLC directed recipients to a website offering a trojanized application. The advisory says the victim company was infected with the FALLCHILL remote-access trojan and attributes the activity to North Korea (HIDDEN COBRA).
- **Psychological/organizational factor (analysis):** The trading-application theme could make a download appear relevant to a person interested in cryptocurrency. This is a plausible lure analysis; the advisory does not establish each recipient's reason for interacting.
- **Impact:** CISA reports infection of the victim company and describes FALLCHILL as a remote-access trojan. The public advisory does not identify that victim or quantify its financial loss.
- **Lessons and controls:** Treat unsolicited software recommendations as untrusted; acquire applications only through independently verified vendor channels; apply application control and endpoint protection; and report suspicious software links. A familiar-looking product name or website is not independent proof of authenticity.
- **Source:** CISA/FBI, *North Korean State-Sponsored Cyber Actors Use AppleJeus Malware to Target Cryptocurrency* (AA21-048A): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a>

## 3. Google and Facebook vendor-invoice fraud

- **Approximate date:** 2013–2015.
- **Organization or context:** Google and Facebook were defrauded through a scheme involving a purported supplier. The US Department of Justice described the matter in its 2019 sentencing announcement.
- **Documented technique:** The DOJ reported that Evaldas Rimasauskas impersonated a Taiwan-based computer-hardware manufacturer and sent fraudulent invoices and related documents to employees at the two companies. Funds were wired to bank accounts controlled by the defendant. This is a vendor-impersonation/BEC-style fraud; the public DOJ summary does not require an assumption that malware or account compromise occurred.
- **Psychological/organizational factor (analysis):** The vendor relationship and invoice/payment workflow provided organizational plausibility. The case supports analysis of trust in a known supplier and process-control weaknesses; it does not establish that a particular employee was psychologically manipulated in a specific way.
- **Impact:** DOJ stated the scheme involved more than $100 million in fraudulent wire transfers. It reported that Rimasauskas was sentenced to five years in prison in March 2019 and ordered to forfeit over $49 million. Those are DOJ-reported figures, not a claim that every transfer was unrecovered.
- **Lessons and controls:** Independently verify vendor bank-account changes using a known contact; separate invoice entry, approval, and payment; require dual authorization above defined thresholds; validate domains and sender details; and escalate unusual payment instructions.
- **Source:** US Department of Justice, US Attorney's Office, Southern District of New York, *Lithuanian Man Sentenced To 5 Years In Prison For Defrauding Google And Facebook Of Over $100 Million* (March 2019): <https://www.justice.gov/usao-sdny/pr/lithuanian-man-sentenced-5-years-prison-defrauding-google-and-facebook-over-100>

## Source limitations and use

Government advisories are authoritative sources for what the issuing agencies publicly reported, but public incident reports may omit victim identities, full timelines, or precise loss attribution. Trigger descriptions above are analysis, not findings about individual victims. This document does not reproduce malicious indicators or links; use the linked advisories for incident-response research under an appropriate educational or defensive context.
