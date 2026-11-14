# PhishShield Module 1: Social Engineering Research

## 1. Purpose and scope

This report is the research foundation for PhishShield, an educational project by Mehak Kansal and Anjali Sharma. It explains common social-engineering concepts and psychological approaches in plain language, while preserving distinctions between verified facts, analysis, and hypotheses. It is not a playbook for contacting real targets. All sample messages in this module are fictional, use reserved `example.com` addresses, and must remain in a controlled classroom setting.

Module 1 is limited to research, detection-indicator documentation, and a reusable labelled dataset. It does not send email, collect credentials, execute attachments, or implement a detection service, campaign, dashboard, Flask application, or database.

## 2. Research methodology and source selection

The research was assembled by reviewing public guidance and incident reporting from CISA, joint US government advisories, and the US Department of Justice. Sources were preferred when they identify the reporting organization, explain the behavior observed, and distinguish confirmed facts from attribution or analysis. Where an incident report does not disclose a victim or quantify loss, this report says so rather than filling gaps with estimates.

Definitions and user-protection advice are grounded primarily in CISA's *Avoiding Social Engineering and Phishing Attacks*. The case studies are based on CISA's joint advisories on the BeagleBoyz and AppleJeus activity and a DOJ release about a vendor-invoice fraud scheme. Links and relevant limits are repeated in [case_studies.md](./case_studies.md).

## 3. Concepts

### Social engineering

- **Definition:** Manipulating people, rather than only exploiting software, to obtain information, access, money, or an action.
- **How it works:** A person may pose as a colleague, service provider, authority figure, or someone with a plausible reason to ask for information. The request can arrive through email, phone, messaging, or in person.
- **Harmless example:** In a classroom exercise, a fictional sender asks a student to confirm a made-up room number for a practice event.
- **Warning signs:** An unverified identity; a request outside normal duties; a demand to bypass a standard process; or pressure not to consult anyone.
- **Prevention:** Verify identity and requests through a separate, known channel; share only information needed for the task; and report suspicious contact using the organization's process.

### Phishing

- **Definition:** A form of social engineering in which a message or website impersonates a trustworthy source to influence a recipient, often to disclose information, open a link or attachment, or make a payment.
- **How it works:** A message gives the recipient a reason to take an action. A link may lead to a deceptive site, or an attachment may contain harmful content. Not every phishing message asks for a password.
- **Harmless example:** A fictional email says that a classroom training account has a sample notice at `https://example.com/training/notice`; the address is reserved and does not provide a real service.
- **Warning signs:** Unexpected requests, mismatched sender details, unclear destinations, pressure, or unrequested attachments. A single sign is not proof.
- **Prevention:** Avoid following unexpected links or opening unexpected files; independently verify the request; use multifactor authentication (MFA); and report suspected messages.

### Spear phishing

- **Definition:** Phishing tailored to a specific person, role, or organization rather than sent as a broadly generic message.
- **How it works:** The sender may use publicly available or previously learned context to make a request seem relevant. Personalization does not establish that the sender is genuine.
- **Harmless example:** A fictional practice email refers to a made-up student club meeting and includes a nonfunctional `example.com` address.
- **Warning signs:** A relevant-seeming message that asks for an unusual action, sensitive data, secrecy, or an exception to procedure.
- **Prevention:** Verify the request with the named person using a separately obtained contact method; follow approval and payment procedures; and avoid oversharing personal or organizational details online.

### Pretexting

- **Definition:** Creating a false or misleading story (a pretext) to make a request appear legitimate.
- **How it works:** The sender establishes a role, situation, or problem—such as an account issue or an urgent administrative task—and uses it to justify a request. Pretexting can occur without email.
- **Harmless example:** In a role-play, a fictional caller says they are helping with a made-up library survey and asks where to find the public schedule.
- **Warning signs:** A story that cannot be checked independently; requests for restricted information; or pressure to keep the interaction secret.
- **Prevention:** Ask for a request or ticket reference, then verify it via an official directory or known support channel. Do not rely on contact details supplied only in the unexpected message.

### Business email compromise (BEC)

- **Definition:** A fraud category in which an attacker uses or impersonates a business email identity to induce a payment, change to payment details, disclosure, or other business action.
- **How it works:** A request may appear to come from an executive, employee, supplier, or service provider. Some BEC uses a compromised real account; other cases use a lookalike or spoofed identity. BEC does not necessarily include malware or a malicious link.
- **Harmless example:** A fictional training message asks a student treasurer to change the payment destination for a made-up club invoice.
- **Warning signs:** A change to bank details, a payment request that bypasses normal approval, secrecy, or an unusual request from a familiar contact.
- **Prevention:** Confirm payment and account changes with a known contact through a separate channel; require dual approval and documented vendor-change checks; and promptly report suspected fraud to finance and security teams.

### Email spoofing

- **Definition:** Forging or altering message identity information so that an email appears to come from a different sender or domain.
- **How it works:** Email has multiple identity-related fields. A displayed sender name, the visible `From` address, the `Reply-To`, and the technical sending path may not all agree. Domain authentication protocols can help receivers assess some kinds of forgery but do not establish that a message's content is safe.
- **Harmless example:** A sample shows the display name “Campus Help Desk” but uses the reserved address `notice@example.com`.
- **Warning signs:** A display-name/address mismatch, an unexpected `Reply-To`, or a domain that differs from an independently known official domain.
- **Prevention:** Inspect full sender details and message headers when appropriate; verify unusual requests using a known channel; and configure and monitor SPF, DKIM, and DMARC for domains the organization controls.

### Malicious links and attachments

- **Definition:** A link or file is malicious when interacting with it can expose a user to fraud, harmful software, or unauthorized access.
- **How it works:** A link can direct to a deceptive or compromised site. An attachment can exploit a vulnerability, run unwanted code, or persuade the recipient to enable unsafe content. An email cannot be judged safe solely from its appearance.
- **Harmless example:** A fictional class message contains the inert URL `https://example.com/class/materials`; no attachment is included in the dataset.
- **Warning signs:** An unexpected file, a request to enable active content, a misleading link label, or a destination different from the one expected.
- **Prevention:** Confirm unexpected files with the sender; use an organization's approved scanning and reporting process; keep software updated; and do not enter credentials after following an unsolicited link.

## 4. Psychological triggers

Research on persuasion and decision-making describes general effects and context-dependent tendencies. The explanations below are useful for awareness, not predictions about a particular person. They are **not claims that every recipient reacts in the same way**. The incident reports establish that a technique was used in a specific case; they generally do not prove which internal psychological process caused a particular recipient to act.

| Technique | Psychological principle (evidence status) | How an attacker may exploit it | Harmless example | Indicators to examine | Safe response |
|---|---|---|---|---|---|
| Urgency and time pressure | Time pressure can reduce the time available for checking and deliberation; effects depend on the person and situation. This is a general observation, not a universal response. | A short deadline is used to discourage verification or normal approval. | “Please review this fictional class reminder by Friday.” | An unusually short deadline, threat of immediate lockout, or instruction to skip checks. | Pause, independently verify, and follow normal approval steps even if the message claims a deadline. |
| Fear and threats | Threats can focus attention on avoiding a negative outcome. Whether they influence someone depends on context and individual differences. | A sender claims an account, job, payment, or service will be lost unless the recipient acts. | A mock notice says a made-up library account needs routine review. | Consequences that are disproportionate, vague, or coupled with an unexpected link or sensitive-data request. | Do not act through the message. Contact the relevant organization using known contact information. |
| Authority and impersonation | People may use role and expertise as cues when deciding whom to trust; this is a tendency, not proof of obedience. | The sender claims to be an executive, administrator, regulator, or IT support person and asks for an exception. | A fictional “Course Coordinator” announces a classroom schedule change. | Authority claim combined with secrecy, payment, credentials, or bypassing policy. | Verify through the directory or a second approver; legitimate authority does not remove verification requirements. |
| Curiosity | Novel or incomplete information can attract attention, but response is not uniform. | A subject hints at a document, result, or unusual event to prompt a click or download. | A fictional bulletin says “See the class notice” and points to an inert example.com page. | Vague “look what I found” language, unexpected files, or unexplained links. | Ask whether the material was expected; confirm with the sender before opening it. |
| Familiarity and trust | Repeated contact and known relationships can support trust, but familiar names and accounts can be impersonated or compromised. | The message refers to a shared activity, colleague, supplier, or previous conversation. | A practice email refers to a made-up student club meeting. | A familiar context paired with an unusual request, changed destination, or unexpected tone. | Verify the unusual part using a previously known phone number or channel. |
| Financial incentives and rewards | Rewards can draw attention and may alter perceived value; this is context-dependent and does not mean recipients will act. | A sender advertises a refund, prize, discount, or payment to prompt disclosure or a click. | A fictional campus notice advertises a made-up participation certificate, with no collection of personal data. | Unsolicited reward, upfront fee, sensitive information requested to claim it, or unclear eligibility. | Check with the purported issuer through its independently verified official channel; do not pay or disclose data to claim an unexpected reward. |

### Established findings versus hypotheses and observations

- **Documented facts:** The sources in [case_studies.md](./case_studies.md) document observed message or impersonation techniques, targeted contexts, and reported outcomes where available.
- **Research-informed generalizations:** Urgency, authority cues, familiarity, curiosity, fear, and reward can influence attention or judgment under some conditions. They are explanatory frameworks, not deterministic rules.
- **Analysis/hypotheses:** Assigning a specific trigger to a particular recipient's decision without direct evidence is an interpretation. Dataset labels such as `psychological_trigger` identify the teaching concept illustrated by the fictional email, not a proven causal response.

## 5. Safe use and ethics

Use the sample data only for classroom demonstrations and offline testing. Do not send the messages to real recipients, modify them into credential collection or malware delivery, or replace `example.com` with a real service. The examples request no actual passwords, payment, or sensitive personal information. If a real suspicious message is encountered, follow the applicable organization's reporting policy.
