# PhishShield Module 1: Detection Indicators

Indicators are evidence to assess, not a checklist in which any one item proves phishing. Human review, sender verification, and technical verification can be needed. Later detection logic should combine signals and preserve uncertainty rather than classify by a single superficial property.

| Indicator | Explanation | Heuristic or technical verification? | Limitations |
|---|---|---|---|
| Sender and `Reply-To` mismatch | The visible sender and the address that receives replies may differ. This can be legitimate (for example, a ticketing or mailing system) or suspicious when unexpected. | **Heuristic** from message fields; verify an unusual request separately. | Mismatch alone does not prove spoofing or malicious intent. |
| Display-name impersonation | A display name can say “IT Support” while the underlying address belongs to another domain or person. | **Heuristic** requiring inspection of the actual address; identity verification is contextual. | Display names are easy to choose and can also be legitimate shared-service names. |
| Unexpected sensitive-information request | A message asks for passwords, MFA codes, bank details, identity documents, or other restricted information. | **Strong contextual heuristic**; confirm policy and request through a separate known channel. | Organizations may request limited information through secure, approved systems. Email should not be assumed to be the approved route. |
| Suspicious or misleading URL | Link text, a displayed destination, and the actual destination may differ. Lookalike spellings, unexpected subdomains, and shortened links may conceal the destination. | **Heuristic** from visible URL; actual destination and reputation require controlled technical inspection. | A domain can be legitimate but compromised; a suspicious-looking URL can also be a benign tracking or vendor URL. Do not visit suspected sites to test them. |
| Unexpected attachment | An unrequested file, especially one prompting macros or other active content, may deliver malware or a deceptive document. | **Heuristic** from context; file analysis belongs in approved, isolated security tooling. | Routine legitimate workflows also use attachments. File extension and appearance alone do not prove safety. |
| Unusual urgency or threats | A deadline, threatened loss, or demand to bypass ordinary checks can discourage independent verification. | **Heuristic** based on message context and normal workflow. | Real notices can have deadlines. Urgency alone is not proof of phishing. |
| Grammar, spelling, or formatting anomalies | Errors or inconsistent branding can be clues that a message is unusual. | **Heuristic** requiring comparison with context and known communications. | Poor grammar does not always indicate phishing; professional-looking email is not necessarily legitimate. Language quality is not an authentication method. |
| SPF evidence | Sender Policy Framework (SPF) lets a domain publish DNS policy identifying hosts authorized to send mail for that domain. A receiver can evaluate a sending IP against that policy. | **Technical verification**: inspect trusted receiving-server authentication results and relevant DNS data. | SPF can pass for a sender domain that is not the brand a recipient thinks is represented; forwarding and configuration affect results. A visible SPF header by itself does not prove that the receiver verified it or that content is safe. |
| DKIM evidence | DomainKeys Identified Mail (DKIM) uses a cryptographic signature to associate a message with a signing domain and detect certain changes after signing. | **Technical verification**: validate the signature using the relevant DNS public key and trusted receiver results. | A valid signature proves neither that the domain is trustworthy nor that the message is benign. The signing domain may not be the visible brand. |
| DMARC evidence | Domain-based Message Authentication, Reporting, and Conformance (DMARC) uses SPF/DKIM alignment with the visible `From` domain and a published policy to guide receiver handling and reporting. | **Technical verification**: interpret trusted receiver results and policy/alignment details. | A DMARC record or header's mere presence does not establish successful authentication. Policy, alignment, receiver handling, and message context matter. |

## Authentication-header cautions

Do not treat the mere presence of `Authentication-Results`, SPF, DKIM, or DMARC text as proof of successful authentication. Results can be inserted or altered outside the trusted mail path. Prefer authentication results added by the receiving organization's trusted mail system, inspect the full relevant headers, and verify DNS and signature information using appropriate procedures. A missing authentication result is not proof of phishing: headers may be stripped, omitted, or unavailable, and not every message path presents the same evidence.

Even when SPF, DKIM, and DMARC all pass, the message could be unwanted, sent by a compromised authorized account, or misleading in its content. Authentication helps answer limited questions about domain authorization and message integrity; it does not determine the sender's intent.

## Recommended approach for a later detector

1. Normalize and parse message fields without discarding the original evidence.
2. Record individual signals with reasons and uncertainty rather than treating a heuristic as a verdict.
3. Use trusted receiver authentication results when available; distinguish unavailable data from a failed check.
4. Treat expected workflow, recipient context, and verified sender history as relevant context.
5. Escalate high-risk requests (credentials, payment changes, or bypassing controls) for independent confirmation.
6. Evaluate false positives, especially for legitimate vendors, newsletters, forwarded mail, and multilingual messages.
