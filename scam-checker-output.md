# Scam checker: output format

Agreed in the team Meet. Every message the checker analyzes returns one JSON object in this shape, as `report` on the result of `SilverShield.check(text)` (`checker/engine.js`). From the command line:

```bash
npm run check -- --json "SBI fraud team here. Your account will be blocked in 2 hours. Share the OTP sent to your phone."
```

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
  "needs_verification": ["sender_number", "link_domain"],
  "links": []
}
```

This is the example from the Meet. For that message the checker returns the same signals, stages, type, risk and action. It differs in three places: the evidence is quoted straight from the text ("SBI", "account will be blocked", "OTP"), `confidence` is 0.84, and `needs_verification` is just `["sender_number"]`, because `link_domain` is only added when the message has a link.

A message with a link adds one entry per link:

```json
"links": [
  {
    "url": "http://paypa1-secure-example.com/login",
    "valid": true,
    "domain": "paypa1-secure-example.com",
    "status": "suspicious",
    "problems": ["brand_lookalike", "not_secure"],
    "official_for": null
  }
]
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
| `scam_type_guess` | string | Best guess at the scam family: `family_emergency`, `government_impersonation`, `toll_or_delivery`, `prize_or_lottery`, `job_or_investment`, `payment_request`, `bank_impersonation`, `company_impersonation`, `phishing_link`, `premium_text_or_call`, `unknown`, or `none`. |
| `risk` | string | One of `likely_scam`, `cannot_tell`, `no_red_flags`. Never "safe" or "legitimate": the checker must not tell someone a message is definitely real. |
| `confidence` | number | 0 to 0.95, how sure the checker is about `risk`. A heuristic from the red-flag score and the word model, not a calibrated probability. `cannot_tell` is always 0.5. |
| `recommended_action` | string | `do_not_respond_verify_via_official_app`, `do_not_respond_call_family_on_known_number`, `verify_via_official_channel_before_acting`, or `no_red_flags_found_stay_careful`. |
| `needs_verification` | string[] | Things the checker cannot confirm from the text alone: `sender_number`, `link_domain` (any link that is not a known official site), `callback_number`. |
| `links` | object[] | Every link found in the message, checked as described below. Empty when there are none. |

## Link checks

Every web address in the message is found (with or without `http://` or `www.`) and checked. Email addresses and file names like `notes.py` are skipped.

| `links[].field` | Meaning |
|---|---|
| `url` | The link exactly as written in the message. |
| `valid` | `false` when it is not a real, well-formed web address: it cannot be parsed, has characters an address cannot have, or ends in something that is not a real top-level domain (checked against IANA's official list in `checker/tlds.js`). |
| `domain` | The part someone actually registered, e.g. `com-track.info` for `usps.com-track.info`. This is who really owns the site. |
| `status` | `not_a_valid_address`, `suspicious`, `official_domain` (a known site of a brand we list), or `no_problems_found`. |
| `problems` | Any of the codes below. |
| `official_for` | The brand whose real site this is, e.g. `"Amazon"` for `amazon.com`, otherwise `null`. |

| Problem | What it catches | Example |
|---|---|---|
| `invalid` | Not a real web address | `https://fastrak.paytoll` |
| `brand_lookalike` | A brand's name on someone else's site, or with swapped letters | `usps.com-trackpkg.info`, `paypa1-secure.com`, `netfIix-billing.com` |
| `brand_mismatch` | The message opens as one company but links somewhere else | "FasTrak: ..." linking to `fastrak-pay-example.xyz` |
| `lookalike_letters` | Letters from another alphabet that look like English ones | `аpple.com` with a Cyrillic а |
| `shortener` | A short link that hides the destination | `bit.ly/...` |
| `ip_address` | Numbers instead of a name | `http://198.51.100.7/login` |
| `at_sign` | A real-looking name before `@`, real destination after it | `http://chase.com@198.51.100.7` |
| `risky_tld` | Cheap endings common in scam texts | `.xyz`, `.top`, `.click`, `.info` |
| `not_secure` | `http://` instead of `https://` (reported, but not enough alone to call a link suspicious) | |

Any problem except `not_secure` makes the link `suspicious` and adds a "bad link" warning sign. Even an `official_domain` link still gets "open the app or type the address yourself": a real address does not make the message real.

Limits: the checker works offline, so it cannot see whether a site is live, who registered it, or where a short link leads. The brand list (in `BRANDS`, `checker/engine.js`) covers about 20 banks, agencies, shippers and tech companies; a look-alike of a brand not on the list is only caught by the other checks.

## Rules of thumb

- Evidence should quote or closely paraphrase the message, so the explanation can point at the exact words.
- The explanation shown to the reader matters as much as the label: "It asks for your OTP. Banks never ask for an OTP over text or phone."
- When signals are weak or conflicting, return `cannot_tell` with low confidence rather than guessing.
