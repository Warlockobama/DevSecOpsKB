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
	// Task list items must emit ac:task-list (interactive Confluence checkboxes),
	// NOT unicode ☐/☑ characters in plain <li> elements.
	if !strings.Contains(out, "<ac:task-list>") {
		t.Errorf("expected ac:task-list macro, got: %s", out)
	}
	if !strings.Contains(out, "<ac:task-status>incomplete</ac:task-status>") {
		t.Errorf("missing incomplete task status: %s", out)
	}
	if !strings.Contains(out, "<ac:task-status>complete</ac:task-status>") {
		t.Errorf("missing complete task status: %s", out)
	}
	if !strings.Contains(out, "<ac:task-body>Pending</ac:task-body>") {
		t.Errorf("missing task body 'Pending': %s", out)
	}
	if !strings.Contains(out, "<ac:task-body>Done</ac:task-body>") {
		t.Errorf("missing task body 'Done': %s", out)
	}
	// Must NOT contain unicode fallback characters
	if strings.Contains(out, "☐") || strings.Contains(out, "☑") {
		t.Errorf("output must not contain unicode checkbox characters: %s", out)
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
	if !strings.Contains(out, `ac:name="code"`) {
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
	if !strings.Contains(out, `ac:name="info"`) {
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
	// Should emit a Confluence page link macro, not plain text
	if !strings.Contains(out, `<ac:link>`) {
		t.Errorf("missing ac:link macro: %s", out)
	}
	if !strings.Contains(out, `ri:content-title="Content Security Policy"`) {
		t.Errorf("missing page title in link: %s", out)
	}
	if !strings.Contains(out, "Content Security Policy") {
		t.Errorf("missing wikilink display text: %s", out)
	}
}

func TestMdToStorage_WikilinkNoDisplay(t *testing.T) {
	out := mdToStorage("See [[fin-1234abcd]]")
	if !strings.Contains(out, `<ac:link>`) {
		t.Errorf("missing ac:link macro: %s", out)
	}
	if !strings.Contains(out, "fin-1234abcd") {
		t.Errorf("missing wikilink text: %s", out)
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
	if !strings.Contains(out, `ac:name="info"`) {
		t.Errorf("missing callout: %s", out)
	}
	if !strings.Contains(out, "Content Security Policy") {
		t.Errorf("missing wikilink text: %s", out)
	}
	if !strings.Contains(out, "<strong>Endpoint:</strong>") {
		t.Errorf("missing bold: %s", out)
	}
	if !strings.Contains(out, `ac:name="code"`) {
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

func TestMdToStorage_OrderedList(t *testing.T) {
	out := mdToStorage("1. first\n2. second\n3. third")
	if !strings.Contains(out, "<ol>") || !strings.Contains(out, "</ol>") {
		t.Errorf("missing ol tags: %s", out)
	}
	if !strings.Contains(out, "<li>first</li>") {
		t.Errorf("missing first item: %s", out)
	}
	if !strings.Contains(out, "<li>second</li>") {
		t.Errorf("missing second item: %s", out)
	}
	if !strings.Contains(out, "<li>third</li>") {
		t.Errorf("missing third item: %s", out)
	}
	// Must not produce unordered list tags
	if strings.Contains(out, "<ul>") {
		t.Errorf("unexpected ul tag in ordered list output: %s", out)
	}
}

func TestMdToStorage_H4H5H6(t *testing.T) {
	cases := []struct {
		md       string
		wantTag  string
		wantText string
	}{
		{"#### H4 Heading", "h4", "H4 Heading"},
		{"##### H5 Heading", "h5", "H5 Heading"},
		{"###### H6 Heading", "h6", "H6 Heading"},
	}
	for _, c := range cases {
		out := mdToStorage(c.md)
		open := "<" + c.wantTag + ">"
		close := "</" + c.wantTag + ">"
		if !strings.Contains(out, open) || !strings.Contains(out, close) {
			t.Errorf("mdToStorage(%q): missing %s tags, got: %s", c.md, c.wantTag, out)
		}
		if !strings.Contains(out, c.wantText) {
			t.Errorf("mdToStorage(%q): missing heading text %q, got: %s", c.md, c.wantText, out)
		}
	}
}

func TestMdToStorage_ItalicFalsePositive(t *testing.T) {
	cases := []string{
		"Content_Type",
		"zap_finding_id",
		"foo_bar_baz",
	}
	for _, input := range cases {
		out := mdToStorage(input)
		if strings.Contains(out, "<em>") {
			t.Errorf("mdToStorage(%q): unexpected <em> tag for identifier with underscores, got: %s", input, out)
		}
	}
}

func TestMdToStorage_ItalicValid(t *testing.T) {
	cases := []struct {
		md   string
		want string
	}{
		{"_italic text_", "<em>italic text</em>"},
		{"_No data yet_", "<em>No data yet</em>"},
		{"prefix _italic_ suffix", "<em>italic</em>"},
	}
	for _, c := range cases {
		out := mdToStorage(c.md)
		if !strings.Contains(out, c.want) {
			t.Errorf("mdToStorage(%q): expected %q in output, got: %s", c.md, c.want, out)
		}
	}
}

func TestMdToStorage_CalloutMultiLine(t *testing.T) {
	md := "> [!Info]\n> Line one\n> Line two\n> Line three"
	out := mdToStorage(md)
	if !strings.Contains(out, `ac:name="info"`) {
		t.Errorf("missing info macro: %s", out)
	}
	// Each line is processed through inlineToStorage individually, then joined
	// with literal <br/> tags so line breaks render in Confluence.
	if !strings.Contains(out, "Line one<br/>Line two") {
		t.Errorf("expected <br/> between callout lines, got: %s", out)
	}
	if !strings.Contains(out, "Line two<br/>Line three") {
		t.Errorf("expected <br/> between second and third callout lines, got: %s", out)
	}
	// Must not join with plain spaces
	if strings.Contains(out, "Line one Line two") {
		t.Errorf("callout lines must not be space-joined, got: %s", out)
	}
}

func TestRiskStatusMacro(t *testing.T) {
	cases := []struct {
		risk      string
		wantColor string
		wantTitle string
	}{
		{"High", "Red", "HIGH"},
		{"high", "Red", "HIGH"},
		{"Medium", "Yellow", "MEDIUM"},
		{"medium", "Yellow", "MEDIUM"},
		{"Low", "Blue", "LOW"},
		{"low", "Blue", "LOW"},
		{"Informational", "Grey", "INFO"},
		{"informational", "Grey", "INFO"},
		{"Info", "Grey", "INFO"},
		{"info", "Grey", "INFO"},
		{"", "Grey", "UNKNOWN"},
		{"Unknown", "Grey", "UNKNOWN"},
	}
	for _, c := range cases {
		out := riskStatusMacro(c.risk)
		if !strings.Contains(out, `ac:name="status"`) {
			t.Errorf("riskStatusMacro(%q): missing status macro name, got: %s", c.risk, out)
		}
		wantColorParam := `<ac:parameter ac:name="colour">` + c.wantColor + `</ac:parameter>`
		if !strings.Contains(out, wantColorParam) {
			t.Errorf("riskStatusMacro(%q): expected colour %q, got: %s", c.risk, c.wantColor, out)
		}
		wantTitleParam := `<ac:parameter ac:name="title">` + c.wantTitle + `</ac:parameter>`
		if !strings.Contains(out, wantTitleParam) {
			t.Errorf("riskStatusMacro(%q): expected title %q, got: %s", c.risk, c.wantTitle, out)
		}
	}
}

func TestPagePropertiesMacro(t *testing.T) {
	t.Run("empty_props_returns_empty", func(t *testing.T) {
		out := pagePropertiesMacro(nil)
		if out != "" {
			t.Errorf("expected empty string for nil props, got: %s", out)
		}
		out = pagePropertiesMacro([][2]string{})
		if out != "" {
			t.Errorf("expected empty string for empty props, got: %s", out)
		}
	})

	t.Run("single_kv", func(t *testing.T) {
		out := pagePropertiesMacro([][2]string{{"Risk", "High"}})
		if !strings.Contains(out, `ac:name="details"`) {
			t.Errorf("missing details macro: %s", out)
		}
		if !strings.Contains(out, "<th>Risk</th>") {
			t.Errorf("missing th key: %s", out)
		}
		if !strings.Contains(out, "<td>High</td>") {
			t.Errorf("missing td value: %s", out)
		}
	})

	t.Run("multiple_kvs", func(t *testing.T) {
		props := [][2]string{
			{"Risk", "Medium"},
			{"Confidence", "High"},
			{"URL", "http://example.com"},
		}
		out := pagePropertiesMacro(props)
		if !strings.Contains(out, "<th>Risk</th>") {
			t.Errorf("missing Risk key: %s", out)
		}
		if !strings.Contains(out, "<th>Confidence</th>") {
			t.Errorf("missing Confidence key: %s", out)
		}
		if !strings.Contains(out, "<th>URL</th>") {
			t.Errorf("missing URL key: %s", out)
		}
		// Verify table structure
		if !strings.Contains(out, "<table><tbody>") {
			t.Errorf("missing table structure: %s", out)
		}
		if !strings.Contains(out, "</tbody></table>") {
			t.Errorf("missing closing table structure: %s", out)
		}
	})

	t.Run("html_escaping_in_keys", func(t *testing.T) {
		out := pagePropertiesMacro([][2]string{{"AT&T", "value"}})
		if strings.Contains(out, "<th>AT&T</th>") {
			t.Errorf("key should be HTML-escaped, got unescaped: %s", out)
		}
		if !strings.Contains(out, "<th>AT&amp;T</th>") {
			t.Errorf("expected HTML-escaped key, got: %s", out)
		}
	})

	t.Run("value_passes_through_unescaped", func(t *testing.T) {
		// Values may contain pre-formatted macros or links
		macro := `<a href="https://example.com">link</a>`
		out := pagePropertiesMacro([][2]string{{"CWE", macro}})
		if !strings.Contains(out, macro) {
			t.Errorf("value should pass through unescaped, got: %s", out)
		}
	})
}

func TestMdToStorage_NestedList(t *testing.T) {
	md := "- Top item\n  - Nested item\n    - Deep nested\n- Another top"
	out := mdToStorage(md)
	// Should produce nested <ul> tags
	ulCount := strings.Count(out, "<ul>")
	if ulCount < 2 {
		t.Errorf("expected at least 2 nested <ul> tags, got %d: %s", ulCount, out)
	}
	if !strings.Contains(out, "<li>Top item</li>") {
		t.Errorf("missing top-level item: %s", out)
	}
	if !strings.Contains(out, "<li>Nested item</li>") {
		t.Errorf("missing nested item: %s", out)
	}
	if !strings.Contains(out, "<li>Deep nested</li>") {
		t.Errorf("missing deep nested item: %s", out)
	}
}

func TestMdToStorage_NestedListWithWikilinks(t *testing.T) {
	md := "- [[findings/fin-abc.md|CSP Issue]] — occurrences: 1\n  - Samples:\n    - [[occurrences/occ-123.md|main.js]]"
	out := mdToStorage(md)
	// Both wikilinks should be ac:link macros
	linkCount := strings.Count(out, "<ac:link>")
	if linkCount < 2 {
		t.Errorf("expected at least 2 ac:link macros, got %d: %s", linkCount, out)
	}
	if !strings.Contains(out, "CSP Issue") {
		t.Errorf("missing finding link text: %s", out)
	}
	if !strings.Contains(out, "main.js") {
		t.Errorf("missing occurrence link text: %s", out)
	}
}

func TestMdToStorage_DetailsToExpandMacro(t *testing.T) {
	md := "## Other info\n\n<details>\n<summary>Show details</summary>\n\nSome detailed content here.\n\n</details>\n\n## Next section"
	out := mdToStorage(md)
	if !strings.Contains(out, `ac:name="expand"`) {
		t.Errorf("missing expand macro: %s", out)
	}
	if !strings.Contains(out, "Show details") {
		t.Errorf("missing expand title: %s", out)
	}
	if !strings.Contains(out, "Some detailed content here") {
		t.Errorf("missing expand content: %s", out)
	}
	// Next section should still render
	if !strings.Contains(out, "<h2>Next section</h2>") {
		t.Errorf("missing section after details: %s", out)
	}
}

func TestMdToStorageWithTitles_ResolvesCorrectly(t *testing.T) {
	titleMap := map[string]string{
		"definitions/10038-csp.md": "Content Security Policy (CSP) Header Not Set (Plugin 10038)",
		"occ-abc123.md":            "Occurrence occ-abc123 — CSP juice-shop",
	}
	md := "- Definition: [[definitions/10038-csp.md|CSP Header]]\n- [[occ-abc123.md|short label]]"
	out := mdToStorageWithTitles(md, titleMap)

	// Definition link should use the actual page title from titleMap
	if !strings.Contains(out, `ri:content-title="Content Security Policy (CSP) Header Not Set (Plugin 10038)"`) {
		t.Errorf("expected resolved definition title from titleMap, got: %s", out)
	}
	// Occurrence link should also use titleMap
	if !strings.Contains(out, `ri:content-title="Occurrence occ-abc123`) {
		t.Errorf("expected resolved occurrence title from titleMap, got: %s", out)
	}
}

// TestMdToStorage_DetailsWithCodeBlock verifies that a <details> block whose
// body contains a fenced code block converts to an expand macro wrapping a
// Confluence code macro — the pattern used by occurrence ## Traffic sections.
func TestMdToStorage_DetailsWithCodeBlock(t *testing.T) {
	md := "## Traffic\n\n" +
		"<details>\n<summary>Show traffic</summary>\n\n" +
		"### Request\n\n" +
		"GET /api/v1/data\n\n" +
		"```http\n{\"key\":\"value\"}\n```\n\n" +
		"### Response\n\nStatus: 200\n\n" +
		"</details>\n"

	out := mdToStorage(md)

	if !strings.Contains(out, `ac:name="expand"`) {
		t.Errorf("expected expand macro, got: %s", out)
	}
	if !strings.Contains(out, "Show traffic") {
		t.Errorf("expand title missing: %s", out)
	}
	// Inner code block should become a Confluence code macro
	if !strings.Contains(out, `ac:name="code"`) {
		t.Errorf("inner code block should become code macro, got: %s", out)
	}
	if !strings.Contains(out, `{"key":"value"}`) {
		t.Errorf("code body should be present, got: %s", out)
	}
	// Headings inside expand should render
	if !strings.Contains(out, "<h3>Request</h3>") {
		t.Errorf("Request heading inside expand macro missing: %s", out)
	}
}

// TestMdToStorage_Snapshots is a table-driven snapshot test covering the full
// breadth of inline and block markdown constructs the converter must handle.
func TestMdToStorage_Snapshots(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantContains []string
	}{
		{
			name:         "H1_heading",
			input:        "# Main Title",
			wantContains: []string{"<h1>Main Title</h1>"},
		},
		{
			name:         "H2_heading",
			input:        "## Section Title",
			wantContains: []string{"<h2>Section Title</h2>"},
		},
		{
			name:         "H3_heading",
			input:        "### Subsection",
			wantContains: []string{"<h3>Subsection</h3>"},
		},
		{
			name:         "bold",
			input:        "**important text**",
			wantContains: []string{"<strong>important text</strong>"},
		},
		{
			name:         "italic",
			input:        "_italic words_",
			wantContains: []string{"<em>italic words</em>"},
		},
		{
			name:  "fenced_code_block_with_language",
			input: "```python\nprint('hello')\n```",
			wantContains: []string{
				`ac:name="code"`,
				"python",
				"print",
			},
		},
		{
			name:         "inline_code",
			input:        "Use `os.Exit(1)` to quit",
			wantContains: []string{"<code>os.Exit(1)</code>"},
		},
		{
			name:  "blockquote_obsidian_warning_callout",
			input: "> [!Warning]\n> Be careful here",
			wantContains: []string{
				`name="warning"`,
				"Be careful here",
			},
		},
		{
			name:  "simple_table_with_header",
			input: "| Name | Value |\n| --- | --- |\n| alpha | 1 |",
			wantContains: []string{
				"<table>",
				"<th>Name</th>",
				"<th>Value</th>",
				"<td>alpha</td>",
				"<td>1</td>",
			},
		},
		{
			name:  "obsidian_wikilink_with_display",
			input: "See [[findings/fin-abc123.md|My Finding]]",
			wantContains: []string{
				"<ac:link>",
				`ri:content-title="My Finding"`,
				"My Finding",
			},
		},
		{
			name:  "external_link",
			input: "[ZAP docs](https://www.zaproxy.org/)",
			wantContains: []string{
				`<a href="https://www.zaproxy.org/">ZAP docs</a>`,
			},
		},
		{
			name:  "bullet_list_with_task_item",
			input: "- [ ] pending task\n- [x] done task\n- normal item",
			wantContains: []string{
				"<ac:task-list>",
				"<ac:task-status>incomplete</ac:task-status>",
				"<ac:task-body>pending task</ac:task-body>",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := mdToStorage(c.input)
			for _, want := range c.wantContains {
				if !strings.Contains(out, want) {
					t.Errorf("mdToStorage(%q): expected %q in output\ngot: %s", c.input, want, out)
				}
			}
		})
	}
}

// TestMdToStorage_AnchorMap_PackageLevel verifies that calling inlineToStorageWithTitles
// multiple times produces consistent output for anchor-mapped links. This is a regression
// guard for the issue where anchorPageMap was rebuilt on every call — behaviour is correct
// (map is rebuilt locally each call, result is deterministic), so two calls must agree.
func TestMdToStorage_AnchorMap_PackageLevel(t *testing.T) {
	input := "[All issues](#issues)"
	out1 := mdToStorage(input)
	out2 := mdToStorage(input)
	if out1 != out2 {
		t.Errorf("inlineToStorageWithTitles is not deterministic across calls:\nfirst:  %s\nsecond: %s", out1, out2)
	}
	// The anchor #issues maps to the "Issues" page
	if !strings.Contains(out1, "Issues") {
		t.Errorf("expected anchor #issues to resolve to Issues page, got: %s", out1)
	}
}

func TestWikilinkToTitle(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"definitions/10038-csp-header-not-set.md", "10038 Csp Header Not Set"},
		{"definitions/100003-cookie-httponly.md", "100003 Cookie Httponly"},
		{"fin-1234abcd", "fin-1234abcd"},
		{"occ-deadbeef", "occ-deadbeef"},
		{"10016-missing-headers.md", "10016 Missing Headers"},
		// No extension, no directory prefix
		{"10001-some-alert", "10001 Some Alert"},
		// Empty path edge case
		{"", ""},
	}
	for _, c := range cases {
		got := wikilinkToTitle(c.path)
		if got != c.want {
			t.Errorf("wikilinkToTitle(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
