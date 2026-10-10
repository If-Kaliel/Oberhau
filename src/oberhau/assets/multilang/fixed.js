// Bounded negative control for the bundled patterns; not a general security guarantee.
const child_process = require("node:child_process");
function fixed(req, res, db) {
  child_process.execFile("echo", ["fixed-fixture"]);
  db.query("SELECT name FROM accounts WHERE name = ?", [req.query.name]);
  db.query({ text: "SELECT name FROM accounts WHERE name = $1", values: [req.query.name] });
  res.json({ value: req.query.html });
  fetch("https://example.invalid/fixed-fixture");
}
// Express serializes object responses as JSON rather than raw HTML.
function jsonObject(req, res) { res.send({value: req.query.html}); }
