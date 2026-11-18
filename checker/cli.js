#!/usr/bin/env node
// Check one message from the command line.
// Usage: node checker/cli.js "message text"   or   echo "message" | node checker/cli.js
//        add --json to print the team report format (see scam-checker-output.md) instead.
"use strict";
const engine = require("./engine.js");
const model = require("./model.js");

const args = process.argv.slice(2);
const json = args.includes("--json");

function show(text) {
  const r = engine.check(text, { model });
  if (json) { console.log(JSON.stringify(r.report, null, 2)); return; }
  console.log(`\nVerdict: ${r.verdictText}  [${r.verdict}]`);
  if (r.flags.length) {
    console.log("\nWarning signs:");
    for (const f of r.flags) console.log(`  - ${f.explanation}${f.match ? `  ("${f.match}")` : ""}`);
  }
  if (r.links.length) {
    console.log("\nLinks:");
    for (const l of r.links) {
      console.log(`  - ${l.url}  [${l.status}]`);
      for (const e of l.explanations) console.log(`      ${e}`);
    }
  }
  if (r.caveat) console.log(`\n${r.caveat}`);
  console.log("\nWhat to do next:");
  r.nextSteps.forEach((s, i) => console.log(`  ${i + 1}. ${s}`));
  console.log("");
}

const arg = args.filter(a => a !== "--json").join(" ").trim();
if (arg) show(arg);
else {
  let buf = "";
  process.stdin.on("data", d => (buf += d)).on("end", () => buf.trim() ? show(buf.trim()) : console.log('Usage: node checker/cli.js [--json] "message text"'));
}
