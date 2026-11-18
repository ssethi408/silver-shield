# Submission

Pencils down at 8:30. Before then:

1. **Push your repo** with this file filled in. No API keys, no private data.
2. **Fill in your team card**: team name, statement number, first names, and the six short answers below.
3. **Hand the card to a judge.** Judges pick six finalists from the cards.
4. **Be ready to demo.** Three minutes, no extra prep time: the concern, the thing working on real data, one honest limit.

## Team card

**Team name:**

**Statement number** (the card your corner wrote):

**First names:**

**Statement:** How might we help **older adults and their families in San Francisco, including Spanish and Chinese speakers,** do **a quick check on an unexpected text before they reply, tap or pay** so that **they don't lose money to a fake toll, bank or family-emergency message**? Build idea: A. We'll know it worked if **the checker flags most current-style scams, explains why in the reader's language, and rarely flags normal texts**.

## Six short answers

**1. The concern:** who, specifically, and what failure would a neighbor recognize?

A grandparent gets "FasTrak: unpaid toll, pay within 24 hours" or "Hi mom, I lost my phone, send money" and pays before asking anyone. Many of those most exposed read Spanish or Chinese first.

**2. What we built,** and the one command that runs it:

A one-screen checker (`index.html`) that gives Likely scam / Cannot tell / No red flags found, the warning signs it found in plain English, Spanish or Chinese, and next steps (reportfraud.ftc.gov, forward to 7726, call the number on your card). It runs offline in the browser. `npm run fetch && npm run eval && npm run serve`

**3. Data we used:** dataset ids from `datasets.json`, how many rows, date range:

`uci-sms-spam`: 5,574 SMS (747 spam), collected around 2012; 3,902 used for training, 1,672 held out for testing. `phishing-multi` (`texts.json`): 600-message sample of short texts (300 phishing/spam, 300 benign), mostly older emails. Plus 22 current-style messages in EN/ES/ZH written by the team.

**4. What it found:** one measured result, with sample size:

On 1,672 held-out UCI texts: 98.3% accuracy, 10.7% of spam not flagged, 0.3% of normal texts flagged. It flagged 10 of 13 current-style scams and raised no false alarms on 9 normal texts. The rules alone caught only 31% of the old UCI spam, so the word model does most of the work on that set and the rules do the work on current scams and on Spanish and Chinese.

**5. One honest limitation:** what it cannot tell you, what breaks:

It does not generalize: on a different source (phishing-multi) accuracy drops to 51.2% on 600 messages. It misses polite scams with no warning words; family-emergency, job and Chinese side-job scams got "Cannot tell". It does not check whether a link or sender is real, and the word model only reads English.

**6. If this were deployed and it failed,** who is accountable, and how would they find out?

Whoever deploys it (a senior center, a library, a bank) owns the outcome and must keep the rules current. It never says a message is safe, which limits the damage a miss can do. To find failures: add a "this was wrong" report button, review flagged and missed cases weekly against new FTC alerts, and re-run `npm run eval` on fresh examples before every change.

## How judges score

Each card is scored 1 to 3 on the first three.

1. **Real concern.** It came from the room, with a specific who and a failure a neighbor would recognize.
2. **Works on real data.** Something runs on real data, and you can show what it found.
3. **Honest.** It names a limitation and says who is accountable if it fails.
4. **Tiebreak.** Would someone outside this room use it?
