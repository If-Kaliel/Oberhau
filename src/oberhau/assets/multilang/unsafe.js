// Static regression fixture only. Never execute this file or install its dependencies.
const child_process = require("node:child_process");
function unsafe(req, res, db) {
  const command = req.query.command;
  child_process.exec(command);
  const query = "SELECT name FROM accounts WHERE name = '" + req.query.name + "'";
  db.query(query);
  db.query({ text: "SELECT name FROM accounts WHERE name = '" + req.query.name + "'" });
  res.send(req.query.html);
  fetch(req.query.url);
}
