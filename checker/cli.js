#!/usr/bin/env node
// Check one message from the command line.
// Usage: node checker/cli.js "message text"   or   echo "message" | node checker/cli.js
"use strict";
const engine = require("./engine.js");
const model = require("./model.js");

function show(text) {
  const r = engine.check(text, { model });
  console.log(`\nVerdict: ${r.verdictText}  [${r.verdict}]`);
  if (r.flags.length) {
    console.log("\nWarning signs:");
    for (const f of r.flags) console.log(`  - ${f.explanation}${f.match ? `  ("${f.match}")` : ""}`);
  }
  if (r.caveat) console.log(`\n${r.caveat}`);
  console.log("\nWhat to do next:");
  r.nextSteps.forEach((s, i) => console.log(`  ${i + 1}. ${s}`));
  console.log("");
}

const arg = process.argv.slice(2).join(" ").trim();
if (arg) show(arg);
else {
  let buf = "";
  process.stdin.on("data", d => (buf += d)).on("end", () => buf.trim() ? show(buf.trim()) : console.log('Usage: node checker/cli.js "message text"'));
}
