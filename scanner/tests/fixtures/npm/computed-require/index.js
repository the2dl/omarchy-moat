// synthetic fixture - never real malware
const cp = require("child" + "_process");
const mod = require(String.fromCharCode(102, 115, 47, 112, 114, 111, 109, 105, 115, 101, 115));
const locale = require("./locale/" + lang);          // ordinary, not a finding
const plugin = require(path.join(__dirname, "p.js")); // ordinary, not a finding
