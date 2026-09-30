package web

import (
	"os/exec"
	"regexp"
	"testing"
)

func TestDockerQuestionsMatchPortAndContainer(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	page, err := FS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	matcher := regexp.MustCompile(`(?s)function questionMatchesRow\(r, q\) \{.*?\n\}`).Find(page)
	if matcher == nil {
		t.Fatal("questionMatchesRow not found")
	}
	script := string(matcher) + `
const assert = require("node:assert/strict");
const q = {peer:"203.0.113.50",dir:"out",proto:"tcp",port:443,containerIP:"172.17.0.2",container:"pub"};
assert.equal(questionMatchesRow({...q}, q), true);
assert.equal(questionMatchesRow({...q,port:80}, q), false);
assert.equal(questionMatchesRow({...q,containerIP:"172.17.0.3"}, q), false);
assert.equal(questionMatchesRow({...q,containerIP:"",container:""}, q), false);
assert.equal(questionMatchesRow({...q,container:""}, q), true);
assert.equal(questionMatchesRow({...q,dir:"in"}, q), false);
const incoming = {...q,dir:"in",port:8080};
assert.equal(questionMatchesRow({...incoming,port:80}, incoming), false);
const host = {...q,containerIP:"",container:""};
assert.equal(questionMatchesRow({...host}, host), true);
assert.equal(questionMatchesRow({...host,port:80}, host), false);
`
	if out, err := exec.Command(node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
