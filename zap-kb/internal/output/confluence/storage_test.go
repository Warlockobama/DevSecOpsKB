package confluence

import (
	"strings"
	"testing"
)

func TestMdToStorage_Headings(t *testing.T) {
	out := mdToStorage("# Title\n## Section\n### Sub")
	if !strings.Contains(out, "<h1>Title</h1>") {
		t.Errorf("missing h1: %s", out)
	}
	if !strings.Contains(out, "<h2>Section</h2>") {
		t.Errorf("missing h2: %s", out)
	}
	if !strings.Contains(out, "<h3>Sub</h3>") {
		t.Errorf("missing h3: %s", out)
	}
}

func TestMdToStorage_Paragraph(t *testing.T) {
	out := mdToStorage("Hello world")
	if !strings.Contains(out, "<p>Hello world</p>") {
		t.Errorf("expected paragraph, got: %s", out)
	}
}

func TestMdToStorage_BulletList(t *testing.T) {
	out := mdToStorage("- Alpha\n- Beta\n- Gamma")
	if !strings.Contains(out, "<ul>") || !strings.Contains(out, "</ul>") {
		t.Errorf("missing ul tags: %s", out)
	}
	if !strings.Contains(out, "<li>Alpha</li>") {
		t.Errorf("missing list item: %s", out)
	}
}

func TestMdToStorage_TaskList(t *testing.T) {
	out := mdToStorage("- [ ] Pending\n- [x] Done")
	if !strings.Contains(out, "☐ Pending") {
		t.Errorf("missing unchecked task: %s", out)
	}
	if !strings.Contains(out, "☑ Done") {
		t.Errorf("missing checked task: %s", out)
	}
}

func TestMdToStorage_Table(t *testing.T) {
	md := "| Status | Count |\n| --- | --- |\n| Open | 5 |"
	out := mdToStorage(md)
	if !strings.Contains(out, "<table>") {
		t.Errorf("missing table tag: %s", out)
	}
	if !strings.Contains(out, "<th>Status</th>") {
		t.Errorf("missing th: %s", out)
	}
	if !strings.Contains(out, "<td>Open</td>") {
		t.Errorf("missing td: %s", out)
	}
	if !strings.Contains(out, "<td>5</td>") {
		t.Errorf("missing value td: %s", out)
	}
}

func TestMdToStorage_Link(t *testing.T) {
	out := mdToStorage("See [ZAP docs](https://www.zaproxy.org/docs/alerts/100003/)")
	if !strings.Contains(out, `<a href="https://www.zaproxy.org/docs/alerts/100003/">ZAP docs</a>`) {
		t.Errorf("missing link: %s", out)
	}
}

func TestMdToStorage_Italic(t *testing.T) {
	out := mdToStorage("_No data yet_")
	if !strings.Contains(out, "<em>No data yet</em>") {
		t.Errorf("missing italic: %s", out)
	}
}

func TestMdToStorage_HTMLEscaping(t *testing.T) {
	out := mdToStorage("Use < and > carefully & always")
	if strings.Contains(out, " < ") || strings.Contains(out, " > ") {
		t.Errorf("unescaped HTML chars: %s", out)
	}
	if !strings.Contains(out, "&lt;") || !strings.Contains(out, "&gt;") || !strings.Contains(out, "&amp;") {
		t.Errorf("expected escaped entities: %s", out)
	}
}

func TestMdToStorage_HorizontalRule(t *testing.T) {
	out := mdToStorage("Before\n\n---\n\nAfter")
	if !strings.Contains(out, "<hr/>") {
		t.Errorf("missing hr: %s", out)
	}
}

func TestMdToStorage_RealDefinitionPage(t *testing.T) {
	md := `# Cookie Set Without HttpOnly Flag (Plugin 100003)

## Detection logic

- Logic: passive
- Docs: [ZAP Docs](https://www.zaproxy.org/docs/alerts/100003/)
`
	out := mdToStorage(md)
	if !strings.Contains(out, "<h1>Cookie Set Without HttpOnly Flag (Plugin 100003)</h1>") {
		t.Errorf("missing h1: %s", out)
	}
	if !strings.Contains(out, "<h2>Detection logic</h2>") {
		t.Errorf("missing h2: %s", out)
	}
	if !strings.Contains(out, "<li>Logic: passive</li>") {
		t.Errorf("missing list item: %s", out)
	}
	if !strings.Contains(out, `href="https://www.zaproxy.org/docs/alerts/100003/"`) {
		t.Errorf("missing link: %s", out)
	}
}

func TestMdToStorage_Bold(t *testing.T) {
	out := mdToStorage("**Risk:** High")
	if !strings.Contains(out, "<strong>Risk:</strong>") {
		t.Errorf("missing bold: %s", out)
	}
}

func TestMdToStorage_InlineCode(t *testing.T) {
	out := mdToStorage("Run `curl http://example.com` to test")
	if !strings.Contains(out, "<code>curl http://example.com</code>") {
		t.Errorf("missing inline code: %s", out)
	}
}

func TestMdToStorage_FencedCodeBlock(t *testing.T) {
	md := "```bash\ncurl \"http://juice-shop:3000\"\n```"
	out := mdToStorage(md)
	if !strings.Contains(out, `name="code"`) {
		t.Errorf("missing code macro: %s", out)
	}
	if !strings.Contains(out, "curl") {
		t.Errorf("missing code content: %s", out)
	}
	if !strings.Contains(out, "bash") {
		t.Errorf("missing language: %s", out)
	}
}

func TestMdToStorage_ObsidianCalloutInfo(t *testing.T) {
	md := "> [!Info]\n> Risk: Medium — Confidence: High"
	out := mdToStorage(md)
	if !strings.Contains(out, `name="info"`) {
		t.Errorf("missing info macro: %s", out)
	}
	if !strings.Contains(out, "Risk: Medium") {
		t.Errorf("missing callout content: %s", out)
	}
}

func TestMdToStorage_ObsidianCalloutWarning(t *testing.T) {
	md := "> [!Warning]\n> This is dangerous"
	out := mdToStorage(md)
	if !strings.Contains(out, `name="warning"`) {
		t.Errorf("missing warning macro: %s", out)
	}
}

func TestMdToStorage_WikilinkWithDisplay(t *testing.T) {
	out := mdToStorage("See [[definitions/10038-csp.md|Content Security Policy]]")
	if strings.Contains(out, "[[") || strings.Contains(out, "]]") {
		t.Errorf("wikilink syntax leaked into output: %s", out)
	}
	if !strings.Contains(out, "Content Security Policy") {
		t.Errorf("missing wikilink display text: %s", out)
	}
}

func TestMdToStorage_WikilinkNoDisplay(t *testing.T) {
	out := mdToStorage("See [[fin-1234abcd]]")
	if strings.Contains(out, "[[") {
		t.Errorf("wikilink syntax leaked: %s", out)
	}
	if !strings.Contains(out, "fin-1234abcd") {
		t.Errorf("missing wikilink path as text: %s", out)
	}
}

func TestMdToStorage_RealFindingPage(t *testing.T) {
	md := `# Issue fin-1161edccd1c5ddc3 — CSPC juice-shop:3000-ddc3

> [!Info]
> Risk: Medium () — Confidence: High

- Definition: [[definitions/10038-csp.md|Content Security Policy (CSP) Header Not Set]]

**Endpoint:** GET http://juice-shop:3000

## Rollup

- Occurrences: 1

## Repro

` + "```bash" + `
curl "http://juice-shop:3000"
` + "```"

	out := mdToStorage(md)
	if !strings.Contains(out, "<h1>") {
		t.Errorf("missing h1: %s", out)
	}
	if !strings.Contains(out, `name="info"`) {
		t.Errorf("missing callout: %s", out)
	}
	if !strings.Contains(out, "Content Security Policy") {
		t.Errorf("missing wikilink text: %s", out)
	}
	if !strings.Contains(out, "<strong>Endpoint:</strong>") {
		t.Errorf("missing bold: %s", out)
	}
	if !strings.Contains(out, `name="code"`) {
		t.Errorf("missing code block: %s", out)
	}
}

func TestParseTableRow(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"| foo | bar |", []string{"foo", "bar"}},
		{"| a | b | c |", []string{"a", "b", "c"}},
		{"| --- | --- |", []string{"---", "---"}},
	}
	for _, c := range cases {
		got := parseTableRow(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseTableRow(%q): got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseTableRow(%q)[%d]: got %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestIsTableSeparator(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"| --- | --- |", true},
		{"| :---: | ---: |", true},
		{"| foo | bar |", false},
		{"| 5 | open |", false},
	}
	for _, c := range cases {
		got := isTableSeparator(c.in)
		if got != c.want {
			t.Errorf("isTableSeparator(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
