package confluence

import (
	"strings"
)

// mdToStorage converts markdown (including Obsidian-flavoured extensions) to
// Confluence storage format (XHTML).
//
// Supported constructs:
//   - Headings: # H1 through ### H3
//   - Paragraphs
//   - Bullet lists: - item (including task lists - [ ] / - [x])
//   - Tables: | col | col | with | --- | separator row
//   - Fenced code blocks: ```lang ... ```
//   - Blockquotes: > text
//   - Obsidian callouts: > [!Info], > [!Warning], > [!Note], > [!Danger]
//   - Horizontal rules: ---
//   - Inline: [text](url), _italic_, **bold**, `code`, [[wikilink|text]]
func mdToStorage(md string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var out strings.Builder

	type blockKind int
	const (
		noBlock    blockKind = iota
		inList               // <ul>
		inTable              // <table>
		inCode               // fenced code block
		inCallout            // Obsidian callout / blockquote
	)

	block := noBlock
	var codeLang string
	var codeLines []string
	calloutKind := ""       // "info", "note", "warning"
	var calloutLines []string

	closeOpenBlocks := func() {
		switch block {
		case inList:
			out.WriteString("</ul>")
		case inTable:
			out.WriteString("</tbody></table>")
		case inCallout:
			body := strings.Join(calloutLines, " ")
			switch calloutKind {
			case "warning":
				out.WriteString(`<ac:structured-macro name="warning"><ac:rich-text-body><p>`)
				out.WriteString(inlineToStorage(body))
				out.WriteString(`</p></ac:rich-text-body></ac:structured-macro>`)
			case "note":
				out.WriteString(`<ac:structured-macro name="note"><ac:rich-text-body><p>`)
				out.WriteString(inlineToStorage(body))
				out.WriteString(`</p></ac:rich-text-body></ac:structured-macro>`)
			default: // info
				out.WriteString(`<ac:structured-macro name="info"><ac:rich-text-body><p>`)
				out.WriteString(inlineToStorage(body))
				out.WriteString(`</p></ac:rich-text-body></ac:structured-macro>`)
			}
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
					out.WriteString(`<ac:structured-macro name="code"><ac:parameter name="language">`)
					out.WriteString(escapeHTML(lang))
					out.WriteString(`</ac:parameter><ac:plain-text-body><![CDATA[`)
					out.WriteString(body)
					out.WriteString(`]]></ac:plain-text-body></ac:structured-macro>`)
				} else {
					out.WriteString(`<ac:structured-macro name="code"><ac:plain-text-body><![CDATA[`)
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
			out.WriteString(`<ac:structured-macro name="info"><ac:rich-text-body><p>`)
			out.WriteString(inlineToStorage(content))
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
		if strings.HasPrefix(trimmed, "### ") {
			closeOpenBlocks()
			out.WriteString("<h3>")
			out.WriteString(inlineToStorage(trimmed[4:]))
			out.WriteString("</h3>")
			continue
		}
		if strings.HasPrefix(trimmed, "## ") {
			closeOpenBlocks()
			out.WriteString("<h2>")
			out.WriteString(inlineToStorage(trimmed[3:]))
			out.WriteString("</h2>")
			continue
		}
		if strings.HasPrefix(trimmed, "# ") {
			closeOpenBlocks()
			out.WriteString("<h1>")
			out.WriteString(inlineToStorage(trimmed[2:]))
			out.WriteString("</h1>")
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
				out.WriteString(inlineToStorage(strings.TrimSpace(cell)))
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

		// --- Bullet list item ---
		if strings.HasPrefix(trimmed, "- ") {
			if block != inList {
				closeOpenBlocks()
				out.WriteString("<ul>")
				block = inList
			}
			item := trimmed[2:]
			if strings.HasPrefix(item, "[ ] ") {
				item = "☐ " + item[4:]
			} else if strings.HasPrefix(item, "[x] ") || strings.HasPrefix(item, "[X] ") {
				item = "☑ " + item[4:]
			}
			out.WriteString("<li>")
			out.WriteString(inlineToStorage(item))
			out.WriteString("</li>")
			continue
		}

		// Close list if we leave list context
		if block == inList {
			closeOpenBlocks()
		}

		// --- Regular paragraph ---
		out.WriteString("<p>")
		out.WriteString(inlineToStorage(trimmed))
		out.WriteString("</p>")
	}

	closeOpenBlocks()
	return out.String()
}

// inlineToStorage converts inline markdown to Confluence storage format.
// Handles: [[wikilink|text]], [text](url), **bold**, _italic_, `code`,
// HTML-escaping.
func inlineToStorage(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		// Obsidian wikilink: [[path|display]] or [[path]]
		if i+1 < len(s) && s[i] == '[' && s[i+1] == '[' {
			end := strings.Index(s[i+2:], "]]")
			if end >= 0 {
				inner := s[i+2 : i+2+end]
				text := inner
				if idx := strings.LastIndex(inner, "|"); idx >= 0 {
					text = inner[idx+1:]
				}
				out.WriteString(escapeHTML(text))
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
						out.WriteString(`<a href="`)
						out.WriteString(escapeAttr(url))
						out.WriteString(`">`)
						out.WriteString(escapeHTML(text))
						out.WriteString(`</a>`)
						i = afterBracket + 1 + closeParen + 1
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

		// Italic: _text_ (not preceded by word char to avoid mid-word)
		if s[i] == '_' && i+1 < len(s) {
			closeUnderscore := strings.Index(s[i+1:], "_")
			if closeUnderscore >= 0 {
				text := s[i+1 : i+1+closeUnderscore]
				if len(text) > 0 && !strings.Contains(text, "\n") {
					out.WriteString("<em>")
					out.WriteString(escapeHTML(text))
					out.WriteString("</em>")
					i = i + 1 + closeUnderscore + 1
					continue
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
