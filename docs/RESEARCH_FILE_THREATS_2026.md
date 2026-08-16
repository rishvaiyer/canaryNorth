# CanaryNorth file threats research, 2026-08-16

Scope: steganography, hidden content, malware scanning, document and file security, and safe forensic evidence handling for CanaryNorth.

## Bottom line

- Steganography hides the existence of communication. Encryption hides content. Hashing fingerprints content. Digital signatures prove origin and integrity. These are related but not interchangeable.
- Hidden text in images, invisible characters, document metadata, hidden layers, archive nesting, and password-protected files are all relevant threat signals, but not all of them are steganography.
- Malware scanning is useful, but it is bounded. A clean verdict only means the scanner observed what it could inspect. If the content is encrypted, password-protected, or otherwise unsupported, CanaryNorth should treat it as unscannable or quarantine it, not call it safe.
- Forensics should preserve evidence without spreading payloads. Log hashes, timestamps, source, scanner version, verdicts, and custody events. Do not store raw hidden payloads or decrypted content in general logs.
- Customer-controlled decryption is the right boundary for protected files. If the service cannot decrypt the item in a controlled way, do not pretend it is fully scanned.

## Source map

| Source | Date | Why it matters | Confidence |
| --- | --- | --- | --- |
| [NIST glossary, steganography](https://csrc.nist.gov/glossary/term/steganography) | current page, accessed 2026-08-16 | Canonical definition of steganography | High |
| [NIST AI 100-4, Reducing Risks Posed by Synthetic Content](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-4.pdf) | published 2024-11-20, updated 2026-04-08 | Current NIST discussion of covert watermarking, false positives, and steganography | High |
| [NIST glossary, hash function](https://csrc.nist.gov/glossary/term/hash_function) | current page, accessed 2026-08-16 | Hashes as fingerprints of files or messages | High |
| [NIST glossary, digital signature](https://csrc.nist.gov/glossary/term/digital_signature) | current page, accessed 2026-08-16 | Signatures provide authenticity and integrity, not confidentiality | High |
| [NIST glossary, chain of custody](https://csrc.nist.gov/glossary/term/chain_of_custody) | current page, accessed 2026-08-16 | Evidence handling and transfer tracking | High |
| [NIST IR 8387, Digital Evidence Preservation](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf) | published 2022-09 | Digital files are easy to change, so source and transfer documentation matter | High |
| [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) | accessed 2026-08-16 | Hidden text, invisible characters, document metadata, and hidden layers are concrete hidden-content risks | High |
| [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) | accessed 2026-08-16 | File metadata, extension tricks, ADS, and comments can bypass naive checks | High |
| [Microsoft Defender for Storage malware scanning intro](https://learn.microsoft.com/en-us/azure/defender-for-cloud/introduction-malware-scanning) | current page, accessed 2026-08-16 | Scan-result channels, tamper warning for index tags, and response automation | High |
| [Microsoft Safe Attachments for SharePoint, OneDrive, and Teams](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-odfb-teams-about) | current page, accessed 2026-08-16 | File locking, quarantine, and asynchronous scanning behavior | High |
| [Microsoft Safe Attachments policy settings](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about) | current page, accessed 2026-08-16 | Password-protected attachments may not fully scan unless a password is available | High |
| [Microsoft 365 anti-malware protection](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about) | current page, accessed 2026-08-16 | Quarantine and false-positive reporting patterns | High |
| [Microsoft cloud security benchmark v2, data protection](https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-v2-data-protection) | current page, accessed 2026-08-16 | Customer-managed keys and Double Key Encryption boundaries | High |
| [Google Cloud, automate malware scanning for files uploaded to Cloud Storage](https://docs.cloud.google.com/architecture/automate-malware-scanning-for-documents-uploaded-to-cloud-storage) | last reviewed 2024-07-16 | Event-driven malware scanning pipeline using ClamAV, Cloud Run, Cloud Logging, and Cloud Monitoring | High |
| [Google Workspace Gmail Security Sandbox](https://knowledge.workspace.google.com/admin/gmail/advanced/set-up-rules-to-detect-harmful-attachments) | accessed 2026-08-16 | Sandbox scanning of attachments and archives, plus quarantine/spam handling | High |
| [Google Workspace DLP for Drive FAQ](https://knowledge.workspace.google.com/admin/security/dlp-for-drive-faq) | accessed 2026-08-16 | Re-scans, file-type targeting, and investigation workflow | Medium |
| [Google Cloud security overview](https://docs.cloud.google.com/docs/security/overview/whitepaper) | accessed 2026-08-16 | Encryption protects data only with the keys | High |
| [Google Cloud VM Threat Detection overview](https://docs.cloud.google.com/security-command-center/docs/concepts-vm-threat-detection-overview) | accessed 2026-08-16 | CSEK/CMEK and Confidential VM boundaries for scanning | High |
| [Azure immutable storage overview](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview) | accessed 2026-08-16 | WORM-style retention and audit logging for evidence or quarantine storage | High |

## What steganography is and is not

- NIST defines steganography as communicating in a way that hides the existence of the communication.
- NIST's 2024 synthetic content report notes a common form of steganography is embedding data in the least significant bits of pixels or other media values.
- Steganography is not encryption. Encryption hides the content, but does not necessarily hide the fact that data is being exchanged.
- Steganography is not the same as hashing or signing. Hashing gives a fingerprint. Signatures give authenticity and integrity. Neither one hides a message.
- In practice, many hidden-content cases are adjacent but distinct:
  - invisible characters in text,
  - document metadata,
  - hidden document layers,
  - alternate data streams,
  - archive nesting,
  - password-protected or client-side encrypted files.
- Recommended CanaryNorth wording: classify these as concealed-content indicators unless there is evidence of actual payload hiding. That keeps the evidence honest and avoids overclaiming.

Confidence: high on the definition boundary, medium on the exact taxonomy because researchers and vendors sometimes use these terms loosely.

## Useful detection signals and false positives

- Media residual anomalies are a strong signal for images and some audio/video formats. NIST and academic steganalysis literature point to residuals, high-pass filters, histogram behavior, DCT coefficients, and other statistical artifacts as common detection surfaces.
- Metadata and structure mismatches are also useful, especially when the visible document looks ordinary but the metadata, layers, comments, or embedded objects do not match the declared file type.
- File upload and container checks matter:
  - extension versus MIME mismatch,
  - double extensions,
  - odd path or filename behavior,
  - archive files carrying executables or scripts,
  - files that rely on comments, hidden sections, or alternate data streams.
- False positives are expected. A published Stegdetect study found the false-positive rate depends heavily on sensitivity and can be quite high on clean image sets.
- That means the operational output should be a risk state, not a pure binary accusation. Good states are `suspected`, `partially scanned`, `unscannable`, `quarantined`, and `confirmed malicious`.

Confidence: high that these are useful signals, medium on any single detector because every format and tool family behaves differently.

## Malware scanning and sandbox boundaries

- Microsoft Defender for Storage scans Azure Storage content and can publish results as blob index tags, security alerts, Event Grid events, and Log Analytics records.
- Microsoft explicitly warns that blob index tags are not tamper-resistant. They are good for quick filtering, but not as the only security control.
- Microsoft Safe Attachments and Google Gmail Security Sandbox both use virtual environments for inspection. Google also scans files inside archive attachments.
- Google Cloud's malware-scanning architecture uses event-driven scanning, ClamAV in Cloud Run, and writes logs to Cloud Logging and metrics to Cloud Monitoring.
- Boundary rule for CanaryNorth: a sandbox verdict is evidence, not truth. If the scanner cannot fully inspect the item, the safe response is quarantine or `unscannable`, not `clean`.
- Microsoft documents that some blobs cannot be scanned when unsupported type or encryption blocks inspection. Google VM Threat Detection also cannot scan disks encrypted with CSEK or CMEK, and cannot scan Confidential VM instances.
- Practical implication: CanaryNorth should separate the scan service from the analyst workstation and from the user-facing UI. The service should emit a verdict and custody record, not raw extracted content.

Confidence: high.

## Logging findings without harmful or private payloads

- Log the minimum set that still supports audit and review:
  - stable object ID or URI,
  - SHA-256 or equivalent hash,
  - file size and type guess,
  - scanner engine and rule version,
  - scan time and verdict,
  - action taken,
  - analyst or system actor,
  - custody event reference.
- NIST describes a hash as a fingerprint of the file or message, and chain of custody as documenting who handled evidence, when, and why.
- NIST IR 8387 emphasizes that digital files are easy to change and that documentation of original source and transfer matters.
- Do not store raw payloads in general logs. Do not log hidden text, extracted secrets, decrypted content, or customer passwords.
- If a sample must be preserved, keep it in a quarantined, access-controlled, immutable store and keep the forensic note separate from the sample itself.
- Azure immutable storage is a useful pattern here because it supports WORM-style retention and audit logs.
- Recommended practice for CanaryNorth is to log a normalized finding record and keep any sensitive object in a sealed evidence bucket, not in the searchable product database.

Confidence: high on the evidence-handling principle, medium on the exact storage pattern because deployment targets may differ.

## Encryption versus signatures versus hashing

- Encryption protects confidentiality. Without the key, the data should not be readable.
- Digital signatures protect authenticity and integrity, and support non-repudiation. They do not provide confidentiality.
- Hashing produces a fixed-length representation of the input. It is useful for fixity, deduplication, and evidence matching, but it does not hide content.
- For CanaryNorth:
  - use hashing to anchor a finding to a specific file,
  - use signatures to attest who approved, exported, or quarantined something,
  - use encryption to protect the underlying payload and any stored evidence.

Confidence: high.

## Retention, quarantine, and customer-controlled decryption

- Quarantine should hold the original object when preservation matters.
- Quarantine should be access-limited, auditable, and, when the risk warrants it, immutable.
- Microsoft gives a useful model for password-protected attachments: if the password is available, it can be used to rescan, and it is not stored.
- Microsoft also documents customer-managed key and Double Key Encryption patterns. DKE is the strongest boundary when the customer must retain decryption control.
- If the service cannot decrypt a file in a controlled way, it should not infer safety. Keep it blocked, quarantined, or marked unscannable.
- Retention should be policy-driven and minimal for ordinary findings, and longer only for evidence, compliance, or customer-directed hold.

Confidence: high on the control pattern, medium on retention duration because that depends on product policy and legal requirements.

## Phased recommendation for CanaryNorth

- Phase 0, metadata-first triage.
  - Hash the file.
  - Record source, timestamp, parser, and verdict.
  - If a file is encrypted, password-protected, or otherwise unsupported, mark it `unscannable` or `quarantined`.
  - Do not store payload bytes in logs.
  - Confidence: high.

- Phase 1, isolated scanning.
  - Run supported files through a sandboxed scanner.
  - Store only normalized verdicts and scanner metadata in the evidence store.
  - Send alerts or event records, not raw files, to downstream automation.
  - Confidence: high.

- Phase 2, controlled decryption.
  - Add a customer-approved unlock path for protected files.
  - Rescan after unlock.
  - Keep passwords and keys out of durable logs.
  - Confidence: medium.

- Phase 3, provenance and attestation.
  - Add signed receipts for what was examined, blocked, forwarded, or exported.
  - Keep signatures separate from raw content.
  - Use immutable retention for evidence when needed.
  - Confidence: medium.

- Non-goals.
  - Do not promise perfect hidden-content detection.
  - Do not use stego markers as the only security signal.
  - Do not make raw hidden payloads searchable.

## Limitations

- Steganalysis is probabilistic. False positives and false negatives are normal.
- Vendor scanners change over time, and feature names differ across Azure, Microsoft 365, Google Workspace, and cloud storage products.
- The strongest evidence here is for images, email attachments, and cloud storage. Audio, video, PDFs, and office docs should get format-specific validation before launch.
- This note is product security guidance, not legal advice or a formal forensic policy.

## Confidence

- High confidence: definitions, hashing versus signatures versus encryption, quarantine-first handling, custody logging, and sandbox boundaries.
- Medium confidence: the exact signal list and the best operational sequencing for mixed-format documents.
- Lower confidence: any promise about complete hidden-content detection, because the available tooling is inherently incomplete and format-dependent.
