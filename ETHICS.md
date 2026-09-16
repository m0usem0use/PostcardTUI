# Ethics & Responsible Use

PostcardTUI is a **dual-use security tool**. The same send that proves your client's domain is unprotected can harass a stranger. This project exists for the first case only.

## The rules

1. **Authorization first.** Only test domains you own or have *written* authorization to test (your engagement's scope document, your own portfolio, your employer's domains with sign-off). If the authorization is ambiguous, it's a no.

2. **Seed inboxes you control.** Stage-2 proof emails go to mailboxes you operate — never to customers, employees, or third parties. A third party receiving your spoof is an unauthorized test no matter how good your intentions.

3. **Minimum volume.** The default cap is 10 emails per run with randomized 8–20s pacing. That's a ceiling, not a quota. One send per domain proves the point; more risks blacklisting your sending IP and crosses into abuse.

4. **Audit-only for everything else.** Stage 1 is passive DNS — it queries public records and touches nobody. If you can't authorize a live send, use audit-only mode (`--audit` or menu option 5). A CRITICAL verdict with records pasted into a report is already 90% of the deliverable.

5. **Remediate, don't just expose.** Every finding ships with the exact DNS fix. The goal of this tool is fewer spoofable domains, not a bigger trophy list.

6. **Disclosure.** Found a hole in someone else's domain during legitimate work? Follow coordinated disclosure: private contact → reasonable timeline → publish. Don't tweet it first.

## Legality

Unauthorized email spoofing and unauthorized access to computer systems are crimes in most jurisdictions — among others:

- US: Computer Fraud and Abuse Act (18 U.S.C. § 1030); CAN-SPAM for unsolicited commercial mail
- UK: Computer Misuse Act 1990
- EU: Directive 2013/40/EU + national implementations
- CAN: Criminal Code s.342

"We were just testing" is not a defense without authorization.

## Maintainer position

This tool is published for defensive security research, pentest engagement delivery, and domain-owner education. The authors accept no liability for misuse and will not provide support for unauthorized targeting. Use it the way you'd want the internet to use it against you.
