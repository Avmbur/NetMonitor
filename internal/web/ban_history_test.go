package web

import (
	"os/exec"
	"regexp"
	"testing"
)

func TestBanHistoryNavigation(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	page, err := FS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script := ""
	for _, name := range []string{"banLive", "banRowShown", "revealBan", "openStormBans", "withFreshBans", "openAlertBan", "banByAlert", "banPackKey", "banPackCells", "banReasonText", "alertHint"} {
		fn := regexp.MustCompile("(?s)function " + name + "\\([^\\n]*\\) \\{.*?\\n\\}").Find(page)
		if fn == nil {
			t.Fatalf("missing function %s", name)
		}
		script += string(fn) + "\n"
	}
	handler := regexp.MustCompile(`(?s)document.getElementById\("policy"\).addEventListener\("input", ev => \{.*?\n\}\);`).Find(page)
	if handler == nil {
		t.Fatal("missing ban address handler")
	}
	script += `
const assert = require("node:assert/strict");
const BANS = [];
const banListQuery = {view:"expired", ip:"192.0.2.99", days:7, pin:"old"};
const ui = {policyExpanded:{}};
const banPackOpen = new Set();
const BAN_PACK_MIN = 10;
const window = {nmLoadBans: () => Promise.resolve()};
const document = {getElementById: () => ({addEventListener: (name, fn) => { input = fn; }})};
let input, revealed = "";
const esc = s => s;
const hostsLabel = () => "all";
const nAddrs = n => String(n);
const remainingDur = () => ({text:"elapsed"});
const banFilterAddr = s => s;
const alertKind = a => a.kind;
const whenText = s => s;
const requestAnimationFrame = () => {};
const setTimeout = () => 0;
const clearTimeout = () => {};
const toastMsg = s => { throw new Error(s); };
function setSection(id) {
  assert.equal(id, "policy");
  const visible = BANS.filter(banRowShown);
  assert.equal(visible.length, 1);
  revealed = visible[0].id;
}
` + string(handler) + `
(async () => {
  const old = {id:"old", ip:"192.0.2.99", state:"expired", source:"scan", hosts:"all", untilMS:1};
  const live = {id:"live", ip:"203.0.113.7", state:"active", source:"scan", hosts:"all", untilMS:Date.now()+60000};
  BANS.push(old, live);
  openStormBans({vm:"h"});
  await Promise.resolve();
  assert.equal(revealed, "live", "storm navigation must reveal a live ban from history");
  openAlertBan({banId:"old", banState:"expired", addr:old.ip});
  await Promise.resolve();
  assert.equal(revealed, "old", "an old alert must open its own ban");
  input({target:{closest: () => ({value:"198.51.100.9"})}});
  assert.equal(banRowShown(old), false, "editing the address must clear the pinned ban");

  assert.equal(banLive({...live, untilMS:Date.now()-1}), false, "expired deadline is not live");
  assert.equal(banLive({...live, untilMS:0}), true, "permanent ban is live");
  assert.notEqual(banPackKey(old), banPackKey(live), "history and live bans must not share a pack");
  const removed = {...old, state:"removed", untilMS:0, ttl:"навсегда"};
  assert.equal(banPackCells({pack:banPackKey(removed), bans:[removed]})[3], "снят");
  assert.equal(banPackCells({pack:banPackKey(old), bans:[old]})[3], "истёк");
  for (const banState of ["expired", "removed"]) {
    assert.equal(alertHint({kind:"scan", banState}).includes("адрес снова не отсечён"), false);
  }
})().catch(err => { console.error(err); process.exitCode = 1; });
`
	if out, err := exec.Command(node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
