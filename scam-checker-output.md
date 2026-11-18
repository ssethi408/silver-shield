# Scam checker: output format

Agreed in the team Meet. Every message the checker analyzes returns one JSON object in this shape. The UI reads it to show the verdict and the plain-language explanation.

## Example

A text claiming to be from SBI's fraud team, saying the account will be blocked in 2 hours unless the reader shares an OTP:

```json
{
  "signals": {
    "impersonation": {"present": true, "evidence": "claims to be SBI fraud team"},
    "urgency": {"present": true, "evidence": "account blocked in 2 hours"},
    "money_ask": {"present": false, "evidence": null},
    "credential_ask": {"present": true, "evidence": "asks for OTP"},
    "secrecy": {"present": false, "evidence": null}
  },
  "scam_stage": ["trust", "urgency", "ask"],
  "scam_type_guess": "bank_impersonation",
  "risk": "likely_scam",
  "confidence": 0.9,
  "recommended_action": "do_not_respond_verify_via_official_app",
  "needs_verification": ["sender_number", "link_domain"]
}
```

## Fields

| Field | Type | Meaning |
|---|---|---|
| `signals` | object | The five red flags the checker looks for. Each has `present` (bool) and `evidence` (the quote or short paraphrase from the message, or `null` when absent). |
| `signals.impersonation` | signal | Claims to be a bank, government agency, company, or someone the reader knows. |
| `signals.urgency` | signal | A deadline or threat: "blocked in 2 hours", "act now", "final notice". |
| `signals.money_ask` | signal | Asks the reader to pay, transfer, buy gift cards, or move money "to keep it safe". |
| `signals.credential_ask` | signal | Asks for an OTP, PIN, password, card number, or login. |
| `signals.secrecy` | signal | Tells the reader not to tell family, the bank, or anyone else. |
| `scam_stage` | string[] | Which stages of the scam playbook appear in the message, in order: `trust` (builds credibility), `urgency` (adds pressure), `ask` (makes the request). |
| `scam_type_guess` | string | Best guess at the scam family, e.g. `bank_impersonation`. |
| `risk` | string | One of `likely_scam`, `cannot_tell`, `no_red_flags_found`. Never "safe" or "legitimate": the checker must not tell someone a message is definitely real. |
| `confidence` | number | 0 to 1, how sure the checker is about `risk`. |
| `recommended_action` | string | What the reader should do next, e.g. `do_not_respond_verify_via_official_app`. The UI turns this into a plain-language sentence. |
| `needs_verification` | string[] | Things the checker cannot confirm from the text alone and the reader should check through an official channel, e.g. `sender_number`, `link_domain`. |

## Rules of thumb

- Evidence should quote or closely paraphrase the message, so the explanation can point at the exact words.
- The explanation shown to the reader matters as much as the label: "It asks for your OTP. Banks never ask for an OTP over text or phone."
- When signals are weak or conflicting, return `cannot_tell` with low confidence rather than guessing.
