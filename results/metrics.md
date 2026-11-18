# Silver Shield: measured results

Generated 2026-11-18 by `npm run eval`. Only messages marked "likely scam" count as caught; "cannot tell" counts as a miss for scams and as no alarm for benign messages.

## Headline

| Test set | Messages | Accuracy | Missed scams | Scams told "no red flags" | False alarms |
|---|---|---|---|---|---|
| UCI SMS, held-out 30% (rules + model) | 1672 (224 scam / 1448 benign) | 98.3% | 10.7% | 4.9% | 0.3% |
| phishing-multi SMS/email sample (unseen source) | 600 (300 scam / 300 benign) | 51.0% | 62.3% | 47.0% | 35.7% |
| Current-style messages, all languages | 26 (16 scam / 10 benign) | 88.5% | 18.8% | 0.0% | 0.0% |

## UCI held-out: which part does the work

| Test set | Messages | Accuracy | Missed scams | Scams told "no red flags" | False alarms |
|---|---|---|---|---|---|
| Red-flag rules only | 1672 (224 scam / 1448 benign) | 90.6% | 68.8% | 23.7% | 0.3% |
| Word model only | 1672 (224 scam / 1448 benign) | 98.6% | 8.5% | 6.3% | 0.3% |
| Rules + model (shipped) | 1672 (224 scam / 1448 benign) | 98.3% | 10.7% | 4.9% | 0.3% |

### Verdict breakdown, UCI held-out

| | Likely scam | Cannot tell | No red flags |
|---|---|---|---|
| Scam | 200 | 13 | 11 |
| Benign | 4 | 23 | 1421 |

### Verdict breakdown, phishing-multi sample

| | Likely scam | Cannot tell | No red flags |
|---|---|---|---|
| Scam | 113 | 46 | 141 |
| Benign | 107 | 42 | 151 |

## Current-style messages by language

| Test set | Messages | Accuracy | Missed scams | Scams told "no red flags" | False alarms |
|---|---|---|---|---|---|
| en | 16 (10 scam / 6 benign) | 87.5% | 20.0% | 0.0% | 0.0% |
| es | 5 (3 scam / 2 benign) | 100.0% | 0.0% | 0.0% | 0.0% |
| zh | 5 (3 scam / 2 benign) | 80.0% | 33.3% | 0.0% | 0.0% |

### Every current-style message

| Label | Kind | Verdict | Flags |
|---|---|---|---|
| scam | en/toll | likely_scam | urgency, delivery_toll, impersonation, bad_link |
| scam | en/package | likely_scam | delivery_toll, impersonation, bad_link |
| scam | en/bank | likely_scam | secrets, urgency, impersonation, wording |
| scam | en/family | cannot_tell | family_secret |
| scam | en/job | cannot_tell | job_invest |
| scam | en/safe_account | likely_scam | money_move, impersonation |
| scam | en/wrong_number | likely_scam | money_move, job_invest |
| scam | es/bank | likely_scam | secrets, urgency, impersonation, bad_link |
| scam | es/family | likely_scam | money_move, urgency, family_secret |
| scam | es/prize | likely_scam | prize, delivery_toll |
| scam | zh/police | likely_scam | money_move, secrets, urgency, family_secret, impersonation |
| scam | zh/package | likely_scam | delivery_toll, bad_link |
| scam | zh/job | cannot_tell | job_invest |
| scam | en/bank_otp | likely_scam | secrets, urgency, impersonation |
| scam | en/lookalike_link | likely_scam | impersonation, bad_link, wording |
| scam | en/invalid_link | likely_scam | impersonation, bad_link, wording |
| benign | en/2fa | cannot_tell |  |
| benign | en/appointment | cannot_tell |  |
| benign | en/personal | no_red_flags |  |
| benign | en/pharmacy | no_red_flags |  |
| benign | en/personal | no_red_flags |  |
| benign | en/official_link | cannot_tell | link |
| benign | es/personal | no_red_flags |  |
| benign | es/appointment | no_red_flags |  |
| benign | zh/personal | no_red_flags |  |
| benign | zh/appointment | no_red_flags |  |

## What it gets wrong (examples)

### UCI scams it missed

- (cannot_tell) Hi, the SEXYCHAT girls are waiting for you to text them. Text now for a great night chatting. send STOP to stop this service
- (cannot_tell) You have 1 new message. Call 0207-083-6089
- (no_red_flags) Xmas & New Years Eve tickets are now on sale from the club, during the day from 10am till 8pm, and on Thurs, Fri & Sat night this week. They
- (no_red_flags) 0A$NETWORKS allow companies to bill for SMS, so they are responsible for their "suppliers", just as a shop has to give a guarantee on what t
- (no_red_flags) Goal! Arsenal 4 (Henry, 7 v Liverpool 2 Henry scores with a simple shot from 6 yards from a pass by Bergkamp to give Arsenal a 2 goal margin
- (no_red_flags) ringtoneking 84484
- (cannot_tell) Not heard from U4 a while. Call me now am here all night with just my knickers on. Make me beg for it like U did last time 01223585236 XX Lu
- (cannot_tell) 2/2 146tf150p

### UCI benign messages it flagged

- (secrets) Please protect yourself from e-threats. SIB never asks for sensitive information like Passwords,ATM/SMS PIN thru email. Never share your pas
- (secrets) Please protect yourself from e-threats. SIB never asks for sensitive information like Passwords,ATM/SMS PIN thru email. Never share your pas
- (secrets) Open rebtel with firefox. When it loads just put plus sign in the user name place, and it will show you two numbers. The lower number is my 
- (secrets) Send me your id and password

### phishing-multi scams it missed

- (no_red_flags) re [ 10 ] : i trust you at six male paranormalhold on matrix
- (no_red_flags) premium online drugs here credo photometry pussy scarecrow crud mentor affiance vide counselor medications from the comfort of our home ! si
- (cannot_tell) ViaProexit list instructions ajrule 
- (no_red_flags) discover how to earn $ 3000 - $ 5000 a week ! change my email preferences
- (no_red_flags) not sure if this is you first only doctor approved pen . is pills and will be the last . if you want to grow / get bigger / larger down ther
- (no_red_flags) your credit score has arrived rli 24881 alicia pkwy lagumar hills , ca 92653 this e - mail message is an advertisement and / or solicitation
- (no_red_flags) something she can ' t refuse
- (no_red_flags) be a hero in bed multiple male orgasms more info here blight gfv shrew pr hoff cv supernatant ecj alexandra by guidance woi nucleolus xe lee

### phishing-multi benign messages it flagged

- (link,wording) URL: http://www.newsisfree.com/click/-4,8272607,1717/ Date: 2002-09-26T11:26:11+01:00(NY Daily News) 
- (wording) schedule crawler : hourahead failure start date : 1 / 27 / 02 ; hourahead hour : 7 ; hourahead schedule download failed . manual interventio
- (wording) schedule crawler : hourahead failure start date : 12 / 12 / 01 ; hourahead hour : 21 ; hourahead schedule download failed . manual intervent
- (wording) enron / hpl actuals for november 27 , 2000 teco tap 20 . 000 / enron ; 100 . 000 / hpl gas daily
- (prize,wording) start date : 12 / 25 / 01 ; hourahead hour : 11 ; start date : 12 / 25 / 01 ; hourahead hour : 11 ; no ancillary schedules awarded . no vari
- (prize,wording) start date : 1 / 15 / 02 ; hourahead hour : 6 ; start date : 1 / 15 / 02 ; hourahead hour : 6 ; no ancillary schedules awarded . no variance
- (impersonation,bad_link)  So I see a headline which reads: "Microsoft Outlining Settlement Plans" and my initial reaction is to wonder if West Jerusalem should worry
- (link,wording) URL: http://www.newsisfree.com/click/-3,8483157,1440/ Date: Not suppliedContrary to popular belief, a new study shows women receive the same

### Current-style scams it missed

- (cannot_tell) Hi mom, I broke my phone, this is my new number. Can you help me pay a bill today? Don't tell dad yet.
- (cannot_tell) Hello! We saw your resume. Part-time remote job, earn $300 per day liking videos. Message us on WhatsApp to start.
- (cannot_tell) 招聘兼职，在家刷单，日赚500元，稳赚不赔，加微信了解。
