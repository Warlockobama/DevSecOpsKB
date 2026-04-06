package confluence

import (
	"fmt"
	"strings"
	"unicode"
)

// mdToStorage converts markdown (including Obsidian-flavoured extensions) to
// Confluence storage format (XHTML).
//
// Supported constructs:
//   - Headings: # H1 through ###### H6
//   - Paragraphs
//   - Bullet lists: - item (including task lists - [ ] / - [x])
//   - Ordered lists: 1. item
//   - Tables: | col | col | with | --- | separator row
//   - Fenced code blocks: ```lang ... ```
//   - Blockquotes: > text
//   - Obsidian callouts: > [!Info], > [!Warning], > [!Note], > [!Danger]
//   - Horizontal rules: ---
//   - Inline: [text](url), _italic_, **bold**, `code`, [[wikilink|text]]
func mdToStorage(md string) string {
	return mdToStorageWithTitles(md, nil)
}

// mdToStorageWithTitles converts markdown to Confluence storage format.
// titleMap maps vault-relative paths (e.g. "definitions/10038-csp.md") to
// the actual Confluence page title, enabling correct wikilink resolution.
func mdToStorageWithTitles(md string, titleMap map[string]string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var out strings.Builder

	// Closure for inline conversion that carries the title map through.
	inline := func(s string) string {
		return inlineToStorageWithTitles(s, titleMap)
	}

	type blockKind int
	const (
		noBlock       blockKind = iota
		inList                  // <ul>
		inTaskList              // <ac:task-list> — interactive Confluence checkboxes
		inOrderedList           // <ol>
		inTable                 // <table>
		inCode                  // fenced code block
		inCallout               // Obsidian callout / blockquote
	)

	block := noBlock
	listDepth := 0 // current nesting depth for bullet lists
	taskID := 0    // monotonically increasing task ID within this page
	var codeLang string
	var codeLines []string
	calloutKind := "" // "info", "note", "warning"
	var calloutLines []string

	closeOpenBlocks := func() {
		switch block {
		case inList:
			for listDepth > 0 {
				out.WriteString("</ul>")
				listDepth--
			}
			out.WriteString("</ul>")
		case inTaskList:
			out.WriteString("</ac:task-list>")
		case inOrderedList:
			out.WriteString("</ol>")
		case inTable:
			out.WriteString("</tbody></table>")
		case inCallout:
			// Process each line through inlineToStorage first, then join with <br/>
			// so the <br/> tags are not HTML-escaped.
			processed := make([]string, len(calloutLines))
			for ci, cl := range calloutLines {
				processed[ci] = inline(cl)
			}
			body := strings.Join(processed, "<br/>")
			macroName := calloutKind
			if macroName == "" {
				macroName = "info"
			}
			out.WriteString(`<ac:structured-macro ac:name="` + macroName + `"><ac:rich-text-body><p>`)
			out.WriteString(body)
			out.WriteString(`</p></ac:rich-text-body></ac:structured-macro>`)
			calloutLines = calloutLines[:0]
			calloutKind = ""
		}
		block = noBlock
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// --- Fenced code block ---
		if block == inCode {
			if strings.HasPrefix(trimmed, "```") {
				// Close code block
				lang := codeLang
				body := strings.Join(codeLines, "\n")
				if lang != "" {
					out.WriteString(`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">`)
					out.WriteString(escapeHTML(lang))
					out.WriteString(`</ac:parameter><ac:plain-text-body><![CDATA[`)
					out.WriteString(body)
					out.WriteString(`]]></ac:plain-text-body></ac:structured-macro>`)
				} else {
					out.WriteString(`<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[`)
					out.WriteString(body)
					out.WriteString(`]]></ac:plain-text-body></ac:structured-macro>`)
				}
				codeLines = codeLines[:0]
				codeLang = ""
				block = noBlock
			} else {
				codeLines = append(codeLines, line)
			}
			continue
		}

		// Open fenced code block
		if strings.HasPrefix(trimmed, "```") {
			closeOpenBlocks()
			codeLang = strings.TrimPrefix(trimmed, "```")
			block = inCode
			continue
		}

		// --- Blockquote / Obsidian callout ---
		if strings.HasPrefix(trimmed, ">") {
			content := strings.TrimSpace(strings.TrimPrefix(trimmed, ">"))

			// Obsidian callout opener: > [!Type]
			if strings.HasPrefix(content, "[!") {
				closeOpenBlocks()
				kind := "info"
				upper := strings.ToUpper(content)
				if strings.Contains(upper, "WARNING") || strings.Contains(upper, "DANGER") || strings.Contains(upper, "CAUTION") {
					kind = "warning"
				} else if strings.Contains(upper, "NOTE") || strings.Contains(upper, "TIP") || strings.Contains(upper, "SUCCESS") {
					kind = "note"
				}
				block = inCallout
				calloutKind = kind
				continue
			}

			// Continuation of callout or plain blockquote
			if block == inCallout {
				if content != "" {
					calloutLines = append(calloutLines, content)
				}
				continue
			}

			// Plain blockquote — close any open block, emit as info macro
			closeOpenBlocks()
			out.WriteString(`<ac:structured-macro ac:name="info"><ac:rich-text-body><p>`)
			out.WriteString(inline(content))
			out.WriteString(`</p></ac:rich-text-body></ac:structured-macro>`)
			continue
		}

		// Non-blockquote line closes open callout
		if block == inCallout {
			closeOpenBlocks()
		}

		// --- Blank line ---
		if trimmed == "" {
			closeOpenBlocks()
			continue
		}

		// --- Heading ---
		if h := headingLevel(trimmed); h > 0 {
			closeOpenBlocks()
			tag := fmt.Sprintf("h%d", h)
			text := strings.TrimSpace(trimmed[h+1:]) // skip "### " prefix
			out.WriteString("<" + tag + ">")
			out.WriteString(inline(text))
			out.WriteString("</" + tag + ">")
			continue
		}

		// --- Horizontal rule ---
		if trimmed == "---" || trimmed == "***" || trimmed == "___" {
			closeOpenBlocks()
			out.WriteString("<hr/>")
			continue
		}

		// --- Table ---
		if strings.HasPrefix(trimmed, "|") {
			if isTableSeparator(trimmed) {
				continue
			}
			cells := parseTableRow(trimmed)
			isHeader := false
			if i+1 < len(lines) {
				if isTableSeparator(strings.TrimSpace(lines[i+1])) {
					isHeader = true
				}
			}
			if block != inTable {
				closeOpenBlocks()
				out.WriteString("<table><tbody>")
				block = inTable
			}
			out.WriteString("<tr>")
			tag := "td"
			if isHeader {
				tag = "th"
			}
			for _, cell := range cells {
				out.WriteString("<")
				out.WriteString(tag)
				out.WriteString(">")
				out.WriteString(inline(strings.TrimSpace(cell)))
				out.WriteString("</")
				out.WriteString(tag)
				out.WriteString(">")
			}
			out.WriteString("</tr>")
			continue
		}

		// Close table if we leave table context
		if block == inTable {
			closeOpenBlocks()
		}

		// --- Bullet list item (with nesting support) ---
		if bulletItem, depth := parseBulletItem(line); bulletItem != "" {
			isTask := strings.HasPrefix(bulletItem, "[ ] ") ||
				strings.HasPrefix(bulletItem, "[x] ") ||
				strings.HasPrefix(bulletItem, "[X] ")

			if isTask {
				// Task list items → Confluence <ac:task-list> (interactive checkboxes)
				if block != inTaskList {
					closeOpenBlocks()
					out.WriteString("<ac:task-list>")
					block = inTaskList
					listDepth = 0
				}
				taskID++
				done := strings.HasPrefix(bulletItem, "[x] ") || strings.HasPrefix(bulletItem, "[X] ")
				status := "incomplete"
				if done {
					status = "complete"
				}
				body := bulletItem[4:] // strip "[ ] " or "[x] "
				out.WriteString("<ac:task>")
				out.WriteString(fmt.Sprintf("<ac:task-id>%d</ac:task-id>", taskID))
				out.WriteString(fmt.Sprintf("<ac:task-status>%s</ac:task-status>", status))
				out.WriteString("<ac:task-body>")
				out.WriteString(inline(body))
				out.WriteString("</ac:task-body>")
				out.WriteString("</ac:task>")
			} else {
				// Regular bullet item → <ul><li>
				if block != inList {
					closeOpenBlocks()
					out.WriteString("<ul>")
					block = inList
					listDepth = 0
				}
				// Adjust nesting depth
				for listDepth < depth {
					out.WriteString("<ul>")
					listDepth++
				}
				for listDepth > depth {
					out.WriteString("</ul>")
					listDepth--
				}
				out.WriteString("<li>")
				out.WriteString(inline(bulletItem))
				out.WriteString("</li>")
			}
			continue
		}

		// Close bullet list if we leave list context
		if block == inList {
			closeOpenBlocks()
		}

		// --- Ordered list item ---
		if olItem := orderedListItem(trimmed); olItem != "" {
			if block != inOrderedList {
				closeOpenBlocks()
				out.WriteString("<ol>")
				block = inOrderedList
			}
			out.WriteString("<li>")
			out.WriteString(inline(olItem))
			out.WriteString("</li>")
			continue
		}

		// Close ordered list if we leave list context
		if block == inOrderedList {
			closeOpenBlocks()
		}

		// --- HTML <details>/<summary> → Confluence expand macro ---
		if strings.HasPrefix(trimmed, "<details>") {
			closeOpenBlocks()
			// Collect content until </details>
			expandTitle := "Details"
			var expandLines []string
			i++
			for i < len(lines) {
				dl := strings.TrimSpace(lines[i])
				if strings.HasPrefix(dl, "<summary>") {
					expandTitle = strings.TrimSuffix(strings.TrimPrefix(dl, "<summary>"), "</summary>")
					i++
					continue
				}
				if strings.HasPrefix(dl, "</details>") {
					break
				}
				expandLines = append(expandLines, lines[i])
				i++
			}
			expandContent := strings.Join(expandLines, "\n")
			out.WriteString(`<ac:structured-macro ac:name="expand"><ac:parameter ac:name="title">`)
			out.WriteString(escapeHTML(expandTitle))
			out.WriteString(`</ac:parameter><ac:rich-text-body>`)
			out.WriteString(mdToStorageWithTitles(expandContent, titleMap))
			out.WriteString(`</ac:rich-text-body></ac:structured-macro>`)
			continue
		}

		// --- Regular paragraph ---
		out.WriteString("<p>")
		out.WriteString(inline(trimmed))
		out.WriteString("</p>")
	}

	closeOpenBlocks()
	return out.String()
}

// inlineToStorage converts inline markdown to Confluence storage format.
// Handles: [[wikilink|text]], [text](url), **bold**, _italic_, `code`,
// HTML-escaping.
func inlineToStorage(s string) string {
	return inlineToStorageWithTitles(s, nil)
}

// inlineToStorageWithTitles converts inline markdown with wikilink title resolution.
func inlineToStorageWithTitles(s string, titleMap map[string]string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		// Obsidian wikilink: [[path|display]] or [[path]]
		// Emit Confluence page link macro so cross-references are navigable.
		if i+1 < len(s) && s[i] == '[' && s[i+1] == '[' {
			end := strings.Index(s[i+2:], "]]")
			if end >= 0 {
				inner := s[i+2 : i+2+end]
				path := inner
				text := inner
				if idx := strings.LastIndex(inner, "|"); idx >= 0 {
					path = inner[:idx]
					text = inner[idx+1:]
				}
				// Resolve page title: titleMap (exact) > display text > wikilinkToTitle fallback
				pageTitle := resolveWikilinkTitle(path, titleMap)
				// If titleMap didn't resolve and display text differs from path,
				// prefer display text (it's usually close to the actual page title).
				if pageTitle == wikilinkToTitle(path) && text != path {
					pageTitle = text
				}
				out.WriteString(`<ac:link><ri:page ri:content-title="`)
				out.WriteString(escapeAttr(pageTitle))
				out.WriteString(`"/><ac:plain-text-link-body><![CDATA[`)
				out.WriteString(text)
				out.WriteString(`]]></ac:plain-text-link-body></ac:link>`)
				i = i + 2 + end + 2
				continue
			}
		}

		// Inline link: [text](url)
		if s[i] == '[' {
			closeBracket := strings.Index(s[i+1:], "]")
			if closeBracket >= 0 {
				afterBracket := i + 1 + closeBracket + 1
				if afterBracket < len(s) && s[afterBracket] == '(' {
					closeParen := strings.Index(s[afterBracket+1:], ")")
					if closeParen >= 0 {
						text := s[i+1 : i+1+closeBracket]
						url := s[afterBracket+1 : afterBracket+1+closeParen]
						i = afterBracket + 1 + closeParen + 1
						// Anchor-only links (#section) — map known KB section anchors to their
						// Confluence folder page titles; others render as bold text.
						if strings.HasPrefix(url, "#") {
							anchorPageMap := map[string]string{
								"#issues":      "Findings",
								"#findings":    "Findings",
								"#occurrences": "Findings",
								"#rules":       "Definitions",
							}
							if pageTitle, ok := anchorPageMap[url]; ok {
								out.WriteString(`<ac:link><ri:page ri:content-title="`)
								out.WriteString(escapeAttr(pageTitle))
								out.WriteString(`"/><ac:plain-text-link-body><![CDATA[`)
								out.WriteString(text)
								out.WriteString(`]]></ac:plain-text-link-body></ac:link>`)
							} else {
								out.WriteString("<strong>")
								out.WriteString(escapeHTML(text))
								out.WriteString("</strong>")
							}
							continue
						}
						// Vault-relative .md links → Confluence page link macro
						if strings.HasSuffix(url, ".md") && !strings.HasPrefix(url, "http") {
							pageTitle := resolveWikilinkTitle(url, titleMap)
							if pageTitle == wikilinkToTitle(url) && text != url {
								pageTitle = text
							}
							out.WriteString(`<ac:link><ri:page ri:content-title="`)
							out.WriteString(escapeAttr(pageTitle))
							out.WriteString(`"/><ac:plain-text-link-body><![CDATA[`)
							out.WriteString(text)
							out.WriteString(`]]></ac:plain-text-link-body></ac:link>`)
							continue
						}
						// External URL
						out.WriteString(`<a href="`)
						out.WriteString(escapeAttr(url))
						out.WriteString(`">`)
						out.WriteString(escapeHTML(text))
						out.WriteString(`</a>`)
						continue
					}
				}
			}
		}

		// Bold: **text**
		if i+1 < len(s) && s[i] == '*' && s[i+1] == '*' {
			close := strings.Index(s[i+2:], "**")
			if close >= 0 {
				text := s[i+2 : i+2+close]
				if len(text) > 0 {
					out.WriteString("<strong>")
					out.WriteString(escapeHTML(text))
					out.WriteString("</strong>")
					i = i + 2 + close + 2
					continue
				}
			}
		}

		// Italic: _text_ — require non-word char (or start/end of string) on both sides
		// to avoid false positives in identifiers like Content_Type or zap_finding.
		if s[i] == '_' && i+1 < len(s) {
			// Must not be preceded by a word character
			if i == 0 || !isWordChar(s[i-1]) {
				closeUnderscore := strings.Index(s[i+1:], "_")
				if closeUnderscore >= 0 {
					afterClose := i + 1 + closeUnderscore + 1
					// Must not be followed by a word character
					if afterClose >= len(s) || !isWordChar(s[afterClose]) {
						text := s[i+1 : i+1+closeUnderscore]
						if len(text) > 0 && !strings.Contains(text, "\n") {
							out.WriteString("<em>")
							out.WriteString(escapeHTML(text))
							out.WriteString("</em>")
							i = afterClose
							continue
						}
					}
				}
			}
		}

		// Inline code: `code`
		if s[i] == '`' {
			closeBack := strings.Index(s[i+1:], "`")
			if closeBack >= 0 {
				text := s[i+1 : i+1+closeBack]
				out.WriteString("<code>")
				out.WriteString(escapeHTML(text))
				out.WriteString("</code>")
				i = i + 1 + closeBack + 1
				continue
			}
		}

		// HTML-escape
		switch s[i] {
		case '&':
			out.WriteString("&amp;")
		case '<':
			out.WriteString("&lt;")
		case '>':
			out.WriteString("&gt;")
		default:
			out.WriteByte(s[i])
		}
		i++
	}
	return out.String()
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func escapeAttr(s string) string {
	s = escapeHTML(s)
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

func isTableSeparator(line string) bool {
	cells := parseTableRow(line)
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		if strings.Trim(strings.TrimSpace(c), ":-") != "" {
			return false
		}
	}
	return true
}

func parseTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, "|")
	parts := strings.Split(line, "|")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		result = append(result, strings.TrimSpace(p))
	}
	return result
}

// parseBulletItem detects a bullet list item at any indentation level.
// Returns (item text, depth) where depth 0 = top-level, 1 = 2-space indent, 2 = 4-space, etc.
// Returns ("", 0) if the line is not a bullet item.
func parseBulletItem(line string) (string, int) {
	// Count leading spaces
	spaces := 0
	for spaces < len(line) && line[spaces] == ' ' {
		spaces++
	}
	rest := line[spaces:]
	if !strings.HasPrefix(rest, "- ") {
		return "", 0
	}
	depth := spaces / 2 // 2 spaces per nesting level
	return strings.TrimSpace(rest[2:]), depth
}

// headingLevel returns 1-6 for lines starting with "# " through "###### ",
// or 0 if the line is not a heading.
func headingLevel(line string) int {
	level := 0
	for level < len(line) && level < 6 && line[level] == '#' {
		level++
	}
	if level == 0 || level >= len(line) || line[level] != ' ' {
		return 0
	}
	return level
}

// orderedListItem returns the item text if line matches "N. text", or empty string.
func orderedListItem(line string) string {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(line)-1 || line[i] != '.' || line[i+1] != ' ' {
		return ""
	}
	return strings.TrimSpace(line[i+2:])
}

// isWordChar returns true if b is a letter, digit, or underscore.
func isWordChar(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b)) || b == '_'
}

// resolveWikilinkTitle resolves a wikilink path to the actual Confluence page title.
// Uses the titleMap for exact match first, then falls back to wikilinkToTitle heuristic.
func resolveWikilinkTitle(path string, titleMap map[string]string) string {
	if titleMap != nil {
		// Try exact path match
		if title, ok := titleMap[path]; ok {
			return title
		}
		// Try without leading directory for same-directory links
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			base := path[idx+1:]
			if title, ok := titleMap[base]; ok {
				return title
			}
		}
	}
	return wikilinkToTitle(path)
}

// wikilinkToTitle derives a Confluence page title from an Obsidian wikilink path.
// e.g. "definitions/10038-csp-header-not-set.md" → "10038 Csp Header Not Set"
// e.g. "fin-1234abcd" → "fin-1234abcd"
func wikilinkToTitle(path string) string {
	// Strip directory prefix and .md extension
	base := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		base = path[idx+1:]
	}
	base = strings.TrimSuffix(base, ".md")
	if base == "" {
		return path
	}
	// If it looks like a definition filename (digits-words), titleize it
	parts := strings.SplitN(base, "-", 2)
	if len(parts) == 2 && len(parts[0]) > 0 && parts[0][0] >= '0' && parts[0][0] <= '9' {
		words := strings.Split(parts[1], "-")
		for i, w := range words {
			if len(w) > 0 {
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		return parts[0] + " " + strings.Join(words, " ")
	}
	return base
}

// pagePropertiesReportMacro returns a Confluence Page Properties Report macro that
// queries all pages with the kb-occurrence label in the given space.
func pagePropertiesReportMacro(spaceKey string) string {
	return fmt.Sprintf(
		`<ac:structured-macro ac:name="page-properties-report" ac:schema-version="1">`+
			`<ac:parameter ac:name="spaceKey">%s</ac:parameter>`+
			`<ac:parameter ac:name="label">kb-occurrence</ac:parameter>`+
			`<ac:parameter ac:name="headings">Status,Owner,Risk,Rule,Finding</ac:parameter>`+
			`<ac:parameter ac:name="sortBy">Risk</ac:parameter>`+
			`</ac:structured-macro>`,
		escapeAttr(spaceKey),
	)
}

// childrenMacro returns a Confluence Children macro that auto-lists child pages
// sorted by title, showing all pages at depth 1.
func childrenMacro() string {
	return `<ac:structured-macro ac:name="children" ac:schema-version="1">` +
		`<ac:parameter ac:name="sort">title</ac:parameter>` +
		`<ac:parameter ac:name="depth">1</ac:parameter>` +
		`<ac:parameter ac:name="all">true</ac:parameter>` +
		`</ac:structured-macro>`
}

// riskStatusMacro returns a Confluence status lozenge macro for the given risk level.
func riskStatusMacro(risk string) string {
	color := "Grey"
	label := strings.ToUpper(strings.TrimSpace(risk))
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		color = "Red"
	case "medium":
		color = "Yellow"
	case "low":
		color = "Blue"
	case "informational", "info":
		color = "Grey"
		label = "INFO"
	}
	if label == "" {
		label = "UNKNOWN"
	}
	return fmt.Sprintf(`<ac:structured-macro ac:name="status"><ac:parameter ac:name="colour">%s</ac:parameter><ac:parameter ac:name="title">%s</ac:parameter></ac:structured-macro>`, color, escapeAttr(label))
}

// pagePropertiesMacro builds a Confluence Page Properties macro from key-value pairs.
// Page Properties macros make metadata searchable and usable in Page Properties Report macros.
//
// SECURITY CONTRACT: keys are HTML-escaped by this function.
// Values are written verbatim into the table cell — they MUST already be safe
// Confluence storage XML (e.g., the output of riskStatusMacro, escapeHTML, or
// a pre-built ac:link element). Callers that pass plain-text values MUST call
// escapeHTML on them first. Passing raw user-controlled strings is an injection risk.
func pagePropertiesMacro(props [][2]string) string {
	if len(props) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<ac:structured-macro ac:name="details"><ac:rich-text-body><table><tbody>`)
	for _, kv := range props {
		b.WriteString("<tr><th>")
		b.WriteString(escapeHTML(kv[0]))
		b.WriteString("</th><td>")
		b.WriteString(kv[1]) // pre-formatted storage XML — see contract above
		b.WriteString("</td></tr>")
	}
	b.WriteString("</tbody></table></ac:rich-text-body></ac:structured-macro>")
	return b.String()
}
