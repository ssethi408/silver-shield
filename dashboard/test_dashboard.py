#!/usr/bin/env python3
"""Smoke-test the generated offline dashboard and its embedded checker/charts."""
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path

PAGE = Path(__file__).with_name("index.html")
NODE = "node"


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.items = []
        self.inside = False
        self.remote = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            if "src" in attrs:
                self.remote.append(attrs["src"])
            self.inside = True
            self.items.append("")
        elif tag == "link" and attrs.get("rel") == "stylesheet" and "href" in attrs:
            self.remote.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "script":
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.items[-1] += data


def main():
    parsed = Scripts()
    page = PAGE.read_text()
    parsed.feed(page)
    assert "__OTHER_CAUGHT__" not in page and "__UCI_CAUGHT__" not in page
    assert "106 of 300" in page and "113 of 300" in page
    assert "Optional: 2012-era SMS spam test" in page
    assert "not texts received recently" in page
    assert "not</em> mean each text was a confirmed fraud attempt" in page
    assert not parsed.remote, parsed.remote
    assert len(parsed.items) == 4, f"Expected offline Plotly + model + engine + dashboard; got {len(parsed.items)}"
    assert "Plotly.newPlot" in parsed.items[0]
    assert "SilverShieldModel" in parsed.items[1]
    assert "SilverShield.check" in parsed.items[3]
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        for i, source in enumerate(parsed.items):
            file = folder / f"script-{i}.js"
            file.write_text(source)
            subprocess.run([NODE, "--check", str(file)], check=True)
        harness = folder / "harness.js"
        harness.write_text(HARNESS)
        subprocess.run([NODE, str(harness)], cwd=folder, check=True)
    print("PASS: all four scripts parse; five Plotly charts render data; live demo updates on typing")


HARNESS = r'''const fs=require('fs'), vm=require('vm'), assert=require('assert');
const plots=[];
class Element {
  constructor(id){this.id=id;this.children=[];this.value=id==='sms'?'FasTrak notice: unpaid toll. Pay within 24 hours to avoid a late fee. [link removed]':'';this.innerHTML='';this.textContent='';this.handlers={};}
  appendChild(x){this.children.push(x);return x;}
  replaceChildren(){this.children=[];this.textContent='';}
  querySelector(){return this;}
  addEventListener(name,fn){this.handlers[name]=fn;}
}
const elements={};
const document={getElementById:id=>elements[id]||(elements[id]=new Element(id)),createElement:t=>new Element(t)};
const ctx={document,Plotly:{newPlot:(id,traces,layout)=>{plots.push({id,traces,layout});return Promise.resolve();}},console};
ctx.window=ctx; vm.createContext(ctx);
for(let i of [1,2,3])vm.runInContext(fs.readFileSync(`script-${i}.js`,'utf8'),ctx,{filename:`script-${i}.js`});
assert.strictEqual(plots.length,5);
for (let p of plots){assert(p.traces.length>0,p.id);for(let tr of p.traces){assert(tr.x.length===tr.y.length,p.id);assert(tr.x.every(n=>Number.isFinite(n)),p.id);}}
assert(elements['cards'].innerHTML.includes('200 / 224'));
assert(elements['cards'].innerHTML.includes('113 / 300'));
assert(elements['cards'].innerHTML.includes('106 / 300'));
assert(elements['demo-result'].children[0].textContent==='Likely scam');
assert(typeof elements['sms'].handlers.input==='function','checker must update on every input event');
elements['sms'].value='今晚七点到家';elements['sms'].handlers.input();
assert(elements['demo-result'].children[0].textContent==='未发现危险信号');
elements['sms'].value='';elements['sms'].handlers.input();
assert(elements['demo-result'].textContent==='Enter a message to check.');
assert(elements['language-table'].children.length===3);
const scam=plots.find(p=>p.id==='scam-chart');
assert(scam&&scam.traces[0].customdata[0][0]===200);
console.log('PASS: chart payload and live checker verified');
'''


if __name__ == "__main__":
    main()
