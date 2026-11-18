#!/usr/bin/env python3
"""Build a single-file, offline Plotly dashboard from the measured checker results.

Run after eval/train_and_eval.js. The checked-in vendor asset is deliberately
optional: fetch the pinned Plotly 2.35.2 bundle once into dashboard/vendor/.
"""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
PLOTLY = HERE / "vendor" / "plotly-2.35.2.min.js"
PLOTLY_SHA256 = "6d21266ce1bd7d9e5ab4e115989c70c20de0382fd973a8f26ab58619eba4d603"


def wilson(k: int, n: int) -> list[float]:
    """95% Wilson score interval, including zero-hit samples."""
    if n == 0:
        return [0.0, 1.0]
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5 / d
    return [round(max(0, c - h), 5), round(min(1, c + h), 5)]


def main() -> None:
    if not PLOTLY.is_file():
        raise SystemExit(
            "Missing Plotly asset. Run: mkdir -p dashboard/vendor && "
            "curl -fsSL https://cdn.plot.ly/plotly-2.35.2.min.js "
            "-o dashboard/vendor/plotly-2.35.2.min.js"
        )
    bundle = PLOTLY.read_bytes()
    if hashlib.sha256(bundle).hexdigest() != PLOTLY_SHA256:
        raise SystemExit("Plotly vendor asset SHA-256 mismatch; refusing to build")
    metrics = json.loads((ROOT / "results" / "metrics.json").read_text())
    cohorts = {
        "UCI SMS held-out": metrics["uciTest"]["combined"],
        "Other-source short texts*": metrics["phishingMulti"]["combined"],
        "Current-style examples†": metrics["current"]["all"],
    }
    for name, m in cohorts.items():
        assert m["scams"] + m["benign"] == m["n"], name
        assert sum(m["table"]["scam"].values()) == m["scams"], name
        assert sum(m["table"]["benign"].values()) == m["benign"], name
        caught = m["table"]["scam"]["likely_scam"]
        alarms = m["table"]["benign"]["likely_scam"]
        assert abs(m["missedScamRate"] - (1 - caught / m["scams"])) < 1e-9, name
        assert abs(m["falseAlarmRate"] - alarms / m["benign"]) < 1e-9, name
        m["caughtInterval"] = wilson(caught, m["scams"])
        m["alarmInterval"] = wilson(alarms, m["benign"])
    payload = {
        "cohorts": cohorts,
        "methods": metrics["uciTest"],
        "languages": {key: metrics["current"][key] for key in ["en", "es", "zh"]},
    }
    payload_js = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    # The dashboard is standalone: charts, checker, and the model work without a server or CDN.
    content = TEMPLATE.replace("__DATE__", html.escape(metrics["generated"]))
    content = content.replace("/*__PLOTLY__*/", bundle.decode("utf-8"))
    for marker, file in [
        ("/*__MODEL__*/", ROOT / "checker" / "model.js"),
        ("/*__ENGINE__*/", ROOT / "checker" / "engine.js"),
    ]:
        content = content.replace(marker, file.read_text())
    content = content.replace("/*__PAYLOAD__*/", payload_js)
    out = HERE / "index.html"
    out.write_text(content)
    print(f"Built {out.relative_to(ROOT)} ({out.stat().st_size:,} bytes), Plotly 2.35.2 offline")
    for name, m in cohorts.items():
        s, b = m["table"]["scam"], m["table"]["benign"]
        print(f"{name}: caught {s['likely_scam']}/{m['scams']}; "
              f"no red flags on {s['no_red_flags']} scams; "
              f"false alarms {b['likely_scam']}/{m['benign']}")


TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Silver Shield | Does the SMS scam checker protect people?</title>
<style>
:root{color-scheme:light;--ink:#182c38;--muted:#526674;--teal:#007f75;--red:#ba4547;--amber:#a66c18;--bg:#f2f6f6;--line:#d9e4e5;--white:#fff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.52 system-ui,-apple-system,Segoe UI,sans-serif}a{color:#056f70}a:focus-visible,button:focus-visible,textarea:focus-visible{outline:3px solid #f2af45;outline-offset:3px}.container{max-width:1200px;margin:auto;padding:0 24px}header{background:#102e39;color:#f9fdfd;padding:24px 0 58px}header a{color:#a3ede4}nav{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;font-size:.87rem;letter-spacing:.04em;text-transform:uppercase}.brand{font-weight:800;letter-spacing:.13em}.eyebrow{color:#82e6d8;text-transform:uppercase;letter-spacing:.16em;font-size:.8rem;font-weight:800;margin:60px 0 10px}h1{font-size:clamp(2.45rem,5.5vw,4.6rem);line-height:1.12;letter-spacing:-.04em;max-width:920px;margin:0 0 18px}header .lead{max-width:800px;font-size:1.24rem;color:#cfe1e4}.hero-note{border-left:4px solid #ffcc76;padding:12px 18px;background:#24434b;max-width:820px;margin-top:26px}main{padding:34px 0 60px}.section{margin:42px 0 58px}h2{font-size:clamp(1.6rem,3.2vw,2.3rem);letter-spacing:-.025em;line-height:1.2;margin:0 0 10px}.section-intro{color:var(--muted);max-width:900px;margin:0 0 20px}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px}.card,.panel{background:var(--white);border:1px solid var(--line);border-radius:15px;box-shadow:0 6px 22px #10313c0b}.card{padding:20px}.card strong{display:block;font-size:2.25rem;line-height:1.2;letter-spacing:-.035em}.card h3{font-size:.91rem;text-transform:uppercase;letter-spacing:.045em;margin:0 0 9px}.card small{display:block;color:var(--muted)}.card p{margin:10px 0 0}.card.good{border-top:5px solid var(--teal)}.card.bad{border-top:5px solid var(--red)}.card.warn{border-top:5px solid var(--amber)}.panel{padding:22px;margin-top:16px}.panel h3{margin:0 0 6px;font-size:1.12rem}.plot{width:100%;min-height:300px}.split{display:grid;grid-template-columns:1fr 1fr;gap:16px}.compact{font-size:.9rem;color:var(--muted)}.callout{padding:17px 20px;border-left:5px solid var(--red);background:#fff3f1;border-radius:3px 12px 12px 3px;margin:20px 0}.callout strong{color:#8e3033}.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.step{padding:22px;background:#e7f3f1;border-radius:14px;border:1px solid #c9e5e0}.step .number{font-weight:800;color:var(--teal);font-size:.85rem;letter-spacing:.08em}.step h3{margin:4px 0 8px}.step p{margin:0}.demo-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.demo textarea{font:inherit;width:100%;min-height:122px;padding:12px;border:1px solid #adbfbe;border-radius:9px;resize:vertical}.demo button{border:0;border-radius:9px;padding:12px 18px;background:var(--teal);color:#fff;font:inherit;font-weight:700;cursor:pointer;margin:10px 0}.result{min-height:160px;background:#edf5f4;border-radius:11px;padding:16px;overflow-wrap:anywhere}.result ul{margin:9px 0;padding-left:22px}.pill{display:inline-block;background:#dcefeb;color:#064f49;font-weight:800;padding:4px 10px;border-radius:99px}.pill.negative{background:#ffe2db;color:#8e3033}.pill.uncertain{background:#fff1d5;color:#76501e}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line)}th{color:#365866}tbody tr:last-child td{border-bottom:0}.table-wrap{overflow:auto}footer{border-top:1px solid var(--line);color:var(--muted);font-size:.87rem;padding:22px 0 42px}.sources{line-height:1.8}code{background:#e5eded;padding:.1em .25em;border-radius:3px}@media(max-width:780px){.cards,.steps,.split,.demo-grid{grid-template-columns:1fr}.container{padding:0 16px}.panel{padding:14px}header{padding-bottom:36px}.eyebrow{margin-top:38px}}
@media print{body{background:white;color:#111}header{background:white;color:#111;padding:8px 0 20px}header .lead,.eyebrow{color:#333}.panel,.card{box-shadow:none}a{color:#075c60}.demo button{display:none}.section{break-inside:avoid}.plot{break-inside:avoid}}
</style>
</head>
<body>
<header><div class="container"><nav><span class="brand">◈ SILVER SHIELD / FIELD EVALUATION</span><a href="#try">Try the live checker ↓</a><span>SMS safety · data run __DATE__ UTC</span></nav>
<p class="eyebrow">A quick check before you reply, tap, or pay</p>
<h1>Can a text checker interrupt a scam?</h1>
<p class="lead">Silver Shield flags suspicious messages, explains the warning signs in English, Spanish or Chinese, and suggests a safer next action. We tested whether it catches labeled scams <em>and</em> whether normal messages trigger alarms.</p>
<p class="hero-note"><strong>The honest answer:</strong> It performs well on old SMS spam, but drops sharply on another source. This is a decision aid—not proof that an unflagged text is genuine.</p></div></header>
<main class="container">
<section class="section demo" aria-labelledby="try"><h2 id="try">01 / Live SMS checker</h2><p class="section-intro">Type or paste a message: the verdict and reasons update instantly. This is the actual Silver Shield engine and trained model from the measured repo, running locally on this page. The sample is invented and its address removed; do not paste private information if presenting on a shared screen.</p><div class="panel demo-grid"><div><label for="sms"><strong>Message to check</strong></label><textarea id="sms">FasTrak notice: unpaid toll. Pay within 24 hours to avoid a late fee. [link removed]</textarea><p class="compact">Results update as you type. A “No red flags” output is never a safety guarantee: verify through a channel you already trust.</p></div><div id="demo-result" class="result" aria-live="polite" aria-atomic="true"></div></div></section>
<section class="section" aria-labelledby="how"><h2 id="how">02 / How it protects a reader</h2><p class="section-intro">Nothing leaves the browser. A word model trained on historical English spam and explainable red-flag rules produce one of three careful outcomes.</p><div class="steps"><div class="step"><div class="number">01 · PAUSE</div><h3>Paste the unexpected text</h3><p>No account, API key, upload, or sender lookup. Do not tap the message's link.</p></div><div class="step"><div class="number">02 · UNDERSTAND</div><h3>Read the warning signs</h3><p>Money requests, verification codes, urgency, look-alike links and family emergencies are explained in the reader's language.</p></div><div class="step"><div class="number">03 · VERIFY OFF-CHANNEL</div><h3>Make a safer next move</h3><p>Call a number you already trust, use the number on your card, and report suspected fraud at <a href="https://reportfraud.ftc.gov/" target="_blank" rel="noopener">reportfraud.ftc.gov</a>.</p></div></div></section>
<section class="section" aria-labelledby="score"><h2 id="score">03 / The measured safety trade-off</h2><p class="section-intro">“Caught” means the exact output <strong>Likely scam</strong>; <strong>Cannot tell</strong> is not counted as a catch. Fraud harm and needless alarms have separate denominators.</p><div class="cards" id="cards"></div>
<div class="panel"><h3>Of labeled spam / phishing texts, what did the reader see?</h3><p class="compact">Percentage within each test set; hover to inspect actual counts. “No red flags” never means safe.</p><div class="plot" id="scam-chart" role="img" aria-label="Stacked outcome bars for labeled scam or spam messages"></div></div>
<div class="panel"><h3>Of labeled normal texts, how many caused an alarm?</h3><p class="compact">Same checker; different denominator. The other-source sample also includes short <em>emails</em>, so it is not an SMS-only field test.</p><div class="plot" id="benign-chart" role="img" aria-label="Stacked outcome bars for labeled benign messages"></div></div>
<div class="callout"><strong>What breaks outside the old benchmark:</strong> On the 600 short texts sampled from another source, 139 of 300 labeled phishing/spam examples received “No red flags”; 106 of 300 benign examples were flagged. This sample mixes emails and SMS, and is class-balanced by design. Do not read its alarm rate as the rate among everyday incoming SMS.</div></section>
<section class="section" aria-labelledby="signals"><h2 id="signals">04 / Why a high benchmark score is not enough</h2><p class="section-intro">A controlled UCI ablation uses the same 1,672 held-out texts for every method. Rules explain modern warning signs; the English word model carries most of the score on older spam. The combined checker can be worse than the model alone on this benchmark.</p><div class="split"><div class="panel"><h3>Spam caught · UCI only</h3><div class="plot" id="method-chart" role="img" aria-label="Spam catch rate by rules only, word model only, and shipped combination"></div></div><div class="panel"><h3>Normal texts falsely flagged · UCI only</h3><div class="plot" id="false-chart" role="img" aria-label="False-alarm counts by rules only, word model only, and shipped combination"></div></div></div><p class="compact">UCI has 224 labeled spam and 1,448 normal SMS in the test split. Its <em>spam</em> label is a proxy, not a verified “fraud” label; data collected circa 2012 cannot certify protection against current scams.</p></section>
<section class="section" aria-labelledby="modern"><h2 id="modern">05 / Recent-style patterns: encouraging, not proof</h2><p class="section-intro">22 team-written examples (13 scam / 9 benign), covering toll, delivery, bank, family and job themes in three languages. They are <em>synthetic, small and potentially aligned with the rules</em>, not a blind real-world validation set.</p><div class="split"><div class="panel"><h3>Scams caught by example language</h3><div class="plot" id="language-chart" role="img" aria-label="Scams caught versus not caught by language in a tiny synthetic set"></div></div><div class="panel"><h3>Sample sizes & uncertainty</h3><div class="table-wrap"><table id="language-table"><thead><tr><th>Language</th><th>Scams caught</th><th>Benign alarms</th></tr></thead><tbody></tbody></table></div><p class="compact">Zero false alarms on 9 normal examples does <em>not</em> establish zero real-world false alarms. A 95% Wilson upper bound is <span id="zero-bound"></span> for 0 of 9.</p></div></div></section>
<section class="section" aria-labelledby="methods"><h2 id="methods">06 / Method, limits, and next test</h2><div class="panel"><div class="table-wrap"><table><thead><tr><th>Test</th><th>Where labels came from</th><th>What the comparison means</th></tr></thead><tbody><tr><td>Historical SMS</td><td><a href="https://archive.ics.uci.edu/dataset/228/sms+spam+collection">UCI SMS Spam Collection</a>; 70% stratified train / 30% held out, seed 17</td><td>1,672 never used in word-model training. Not modern fraud labels.</td></tr><tr><td>Different source</td><td><a href="https://huggingface.co/datasets/ealvaradob/phishing-dataset">phishing-multi texts.json</a>; 300 per class, lengths 20–300, exact-match UCI duplicates removed</td><td>600 short emails and SMS, sampled from 3,342 eligible rows. Different source, not SMS-only or naturally distributed.</td></tr><tr><td>Current-style examples</td><td>22 team-written labeled examples; English / Spanish / Chinese</td><td>Small illustrative smoke test; wording may overlap rules.</td></tr></tbody></table></div><p class="compact">Metrics: scam catch rate = “Likely scam” / labeled spam or phishing; miss rate = (“Cannot tell” + “No red flags”) / labeled spam or phishing; false-alarm rate = “Likely scam” / labeled benign. Existing repo “accuracy” treats “Cannot tell” on benign as no alarm, so this dashboard emphasizes catch rate and false alarms separately. Uncertainty bounds use 95% Wilson intervals for binomial proportions, conditional on these sample selections.</p><p><strong>Next gate before deployment:</strong> independently label a newer, SMS-only, multilingual set with non-scam lookalikes; test blinded and track “No red flags” on confirmed scams. A community organization must review failures regularly and own the update process.</p></div></section>
</main><footer class="container"><div class="sources">Source: <a href="https://github.com/ssethi408/silver-shield">Silver Shield checker and evaluation</a> · <a href="https://github.com/sergeicu/trust-safety-impact-lab/blob/main/05-personal-safety.md">Personal Safety challenge</a> · Plotly.js 2.35.2 (bundled offline) · Rebuild: <code>node eval/train_and_eval.js</code>, then <code>python3 dashboard/build_dashboard.py</code>.</div><div>* Other-source length-filtered phishing/benign texts, including emails. † Synthetic current-style messages, not independently collected. Evaluation generated __DATE__ UTC.</div></footer>
<script>/*__PLOTLY__*/</script>
<script>/*__MODEL__*/</script>
<script>/*__ENGINE__*/</script>
<script>const DATA = /*__PAYLOAD__*/;
(function () {
'use strict';
const colors={caught:'#007f75',maybe:'#e4ac4e',no:'#bd4c50',normal:'#95c6bf',alarm:'#bd4c50',text:'#182c38',grid:'#e8eeee'};
const cohorts=DATA.cohorts, names=Object.keys(cohorts), percent=n=>(100*n).toFixed(1)+'%', byId=id=>document.getElementById(id);
const vals=(m,label)=>['likely_scam','cannot_tell','no_red_flags'].map(v=>m.table[label][v]);
const fmt=(count,denom)=>count+' / '+denom;
function plot(id, traces, layout){return Plotly.newPlot(id,traces,Object.assign({font:{family:'system-ui, sans-serif',color:colors.text,size:13},paper_bgcolor:'#ffffff',plot_bgcolor:'#ffffff',margin:{l:188,r:20,t:18,b:35},showlegend:true,legend:{orientation:'h',y:-.2},hovermode:'closest'},layout),{responsive:true,displaylogo:false,modeBarButtonsToRemove:['lasso2d','select2d']});}
function makeStack(id,label){let order=['likely_scam','cannot_tell','no_red_flags'], labels=label==='scam'?['Likely scam · caught','Cannot tell · not caught','No red flags · not caught']:['Likely scam · false alarm','Cannot tell · no alarm','No red flags · no alarm'];let palette=label==='scam'?[colors.caught,colors.maybe,colors.no]:[colors.alarm,colors.maybe,colors.normal];let traces=order.map((key,j)=>({type:'bar',orientation:'h',name:labels[j],y:names,x:names.map(n=>cohorts[n].table[label][key]/cohorts[n][label==='scam'?'scams':'benign']*100),customdata:names.map(n=>[cohorts[n].table[label][key],cohorts[n][label==='scam'?'scams':'benign']]),marker:{color:palette[j]},hovertemplate:'%{y}<br>'+labels[j]+': %{customdata[0]} of %{customdata[1]} (%{x:.1f}%)<extra></extra>',text:names.map(n=>{let x=cohorts[n].table[label][key]/cohorts[n][label==='scam'?'scams':'benign'];return x>.085?percent(x):''}),textposition:'inside',insidetextanchor:'middle'}));plot(id,traces,{barmode:'stack',height:310,xaxis:{range:[0,100],ticksuffix:'%',gridcolor:colors.grid},yaxis:{autorange:'reversed',automargin:true},margin:{l:195,r:20,t:12,b:50},uniformtext:{minsize:10,mode:'hide'}});}
let u=cohorts[names[0]], e=cohorts[names[1]], c=cohorts[names[2]];
const metricCard=(cls,title,number,body,detail)=>'<article class="card '+cls+'"><h3>'+title+'</h3><strong>'+number+'</strong><p>'+body+'</p><small>'+detail+'</small></article>';
byId('cards').innerHTML=metricCard('good','Historical SMS caught',fmt(u.table.scam.likely_scam,u.scams),percent(u.table.scam.likely_scam/u.scams)+' of held-out UCI spam identified','95% Wilson interval '+percent(u.caughtInterval[0])+'–'+percent(u.caughtInterval[1])+' · 1,672 SMS tested')+metricCard('bad','Different-source texts caught',fmt(e.table.scam.likely_scam,e.scams),percent(e.table.scam.likely_scam/e.scams)+' of labeled phishing/spam identified','95% Wilson interval '+percent(e.caughtInterval[0])+'–'+percent(e.caughtInterval[1])+' · 600 short texts tested')+metricCard('warn','Current-style examples caught',fmt(c.table.scam.likely_scam,c.scams),percent(c.table.scam.likely_scam/c.scams)+' of synthetic scams identified','95% Wilson interval '+percent(c.caughtInterval[0])+'–'+percent(c.caughtInterval[1])+' · 22 examples tested');
makeStack('scam-chart','scam');makeStack('benign-chart','benign');
let methods=[['Rules only',DATA.methods.rulesOnly],['Model only',DATA.methods.modelOnly],['Combined · shipped',DATA.methods.combined]];
plot('method-chart',[{type:'bar',orientation:'h',y:methods.map(x=>x[0]),x:methods.map(x=>x[1].table.scam.likely_scam/x[1].scams*100),marker:{color:[colors.maybe,colors.caught,'#196c94']},text:methods.map(x=>fmt(x[1].table.scam.likely_scam,x[1].scams)),textposition:'auto',hovertemplate:'%{y}: %{text} spam caught (%{x:.1f}%)<extra></extra>'}],{height:285,showlegend:false,xaxis:{range:[0,100],ticksuffix:'%',gridcolor:colors.grid},yaxis:{autorange:'reversed'},margin:{l:145,r:12,t:14,b:40}});
plot('false-chart',[{type:'bar',orientation:'h',y:methods.map(x=>x[0]),x:methods.map(x=>x[1].table.benign.likely_scam),marker:{color:[colors.maybe,colors.caught,'#196c94']},text:methods.map(x=>fmt(x[1].table.benign.likely_scam,x[1].benign)),textposition:'auto',hovertemplate:'%{y}: %{text} normal SMS flagged<extra></extra>'}],{height:285,showlegend:false,xaxis:{range:[0,7],dtick:1,title:'Count (out of 1,448)',gridcolor:colors.grid},yaxis:{autorange:'reversed'},margin:{l:145,r:12,t:14,b:48}});
let langs=[['English',DATA.languages.en],['Spanish',DATA.languages.es],['Chinese',DATA.languages.zh]];
plot('language-chart',[{type:'bar',orientation:'h',name:'Likely scam · caught',y:langs.map(x=>x[0]),x:langs.map(x=>x[1].table.scam.likely_scam),marker:{color:colors.caught},hovertemplate:'%{y}: %{x} caught<extra></extra>'},{type:'bar',orientation:'h',name:'Not caught',y:langs.map(x=>x[0]),x:langs.map(x=>x[1].scams-x[1].table.scam.likely_scam),marker:{color:colors.no},hovertemplate:'%{y}: %{x} not caught<extra></extra>'}],{barmode:'stack',height:290,xaxis:{dtick:1,title:'Synthetic scam examples',gridcolor:colors.grid},yaxis:{autorange:'reversed'},margin:{l:100,r:15,t:15,b:50}});
langs.forEach(([name,m])=>{let tr=document.createElement('tr');[name,fmt(m.table.scam.likely_scam,m.scams),fmt(m.table.benign.likely_scam,m.benign)].forEach(s=>{let td=document.createElement('td');td.textContent=s;tr.appendChild(td)});byId('language-table').querySelector('tbody').appendChild(tr)});
byId('zero-bound').textContent=percent(c.alarmInterval[1]);
function check(){let raw=byId('sms').value.trim(),out=byId('demo-result');out.replaceChildren();if(!raw){out.textContent='Enter a message to check.';return}let r=SilverShield.check(raw,{model:SilverShieldModel}),h=document.createElement('strong');h.className='pill '+(r.verdict==='likely_scam'?'negative':r.verdict==='cannot_tell'?'uncertain':'');h.textContent=r.verdictText;out.appendChild(h);let p=document.createElement('p');p.textContent=r.flags.length?'Why: '+r.flags.map(f=>f.explanation).join(' '):'No known warning signs were detected. That does not mean the message is genuine.';out.appendChild(p);if(r.caveat){let caveat=document.createElement('p');caveat.textContent=r.caveat;out.appendChild(caveat)}let heading=document.createElement('strong');heading.textContent='Safer next steps';out.appendChild(heading);let ul=document.createElement('ul');r.nextSteps.slice(0,4).forEach(s=>{let li=document.createElement('li');li.textContent=s;ul.appendChild(li)});out.appendChild(ul)}
byId('sms').addEventListener('input',check);check();
})();</script>
</body></html>'''


if __name__ == "__main__":
    main()
