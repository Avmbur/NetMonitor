package web

import (
	"regexp"
	"strings"
	"testing"
)

// Скрипт морды не должен звать функцию, которой в нём нет: такой вызов
// падает только по клику (ПКМ, окно правила), node --check его не видит.
func TestScriptCallsOnlyDefinedFunctions(t *testing.T) {
	b, err := FS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	scripts := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`).FindAllStringSubmatchIndex(page, -1)
	if len(scripts) == 0 {
		t.Fatal("в index.html нет скрипта")
	}
	const ident = `[A-Za-z_$][\w$]*`
	identRe := regexp.MustCompile(ident)
	known := map[string]bool{}
	for _, re := range []string{
		`\bfunction\s+(` + ident + `)`,
		`\b(?:const|let|var)\s+(` + ident + `)`,
		`\b(?:const|let|var)\s*[\{\[]([^\]\}]*)[\]\}]`,
		`\bfunction\s*(?:` + ident + `)?\s*\(([^)]*)\)`,
		`\(([^()]*)\)\s*=>`,
		`(` + ident + `)\s*=>`,
	} {
		r := regexp.MustCompile(re)
		for _, s := range scripts {
			for _, m := range r.FindAllStringSubmatch(page[s[2]:s[3]], -1) {
				for _, n := range identRe.FindAllString(m[1], -1) {
					known[n] = true
				}
			}
		}
	}
	// Ключевые слова, встроенное в браузер и CSS-функции в строках стилей.
	for _, n := range strings.Fields(`if for while switch catch function return typeof await new of in do else void delete
		Array Object String Number Boolean Date Set Map WeakMap Promise Error RegExp JSON Math Intl Symbol
		Audio Blob File FileReader URL URLSearchParams Image
		fetch setTimeout clearTimeout setInterval clearInterval requestAnimationFrame cancelAnimationFrame
		parseInt parseFloat isNaN isFinite encodeURIComponent decodeURIComponent getComputedStyle alert confirm
		minmax repeat calc var rgba rgb`) {
		known[n] = true
	}

	call := regexp.MustCompile(`(` + ident + `)\s*\(`)
	for _, s := range scripts {
		src := page[s[2]:s[3]]
		for _, m := range call.FindAllStringSubmatchIndex(src, -1) {
			if m[0] > 0 && strings.ContainsRune("._$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", rune(src[m[0]-1])) {
				continue
			}
			if n := src[m[2]:m[3]]; !known[n] {
				line := strings.Count(page[:s[2]+m[0]], "\n") + 1
				t.Errorf("index.html:%d: вызов %s(), а функции %s в скрипте нет", line, n, n)
			}
		}
	}
}
