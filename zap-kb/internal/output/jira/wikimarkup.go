package jira

import (
	"fmt"
	"strings"
)

// renderWikiDoc renders an ADF node tree as Jira wiki markup — the description
// format Jira Data Center's REST v2 expects. Reusing the tree built by
// buildDescription / buildEpicDescription keeps Cloud and Data Center issue
// bodies identical in content; only the serialization differs.
func renderWikiDoc(doc adfDoc) string {
	var b strings.Builder
	for _, node := range doc.Content {
		block := renderWikiBlock(node)
		if block == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(block)
	}
	return b.String()
}

func renderWikiBlock(node any) string {
	switch n := node.(type) {
	case adfParagraph:
		return renderWikiInline(n.Content)
	case adfHeading:
		return fmt.Sprintf("h%d. %s", n.Attrs.Level, renderWikiInline(n.Content))
	case adfCodeBlock:
		body := neutralizeWikiMacros(renderWikiInline(n.Content))
		if lang := strings.TrimSpace(n.Attrs.Language); lang != "" {
			return "{code:" + lang + "}\n" + body + "\n{code}"
		}
		return "{code}\n" + body + "\n{code}"
	}
	return ""
}

func renderWikiInline(nodes []any) string {
	var b strings.Builder
	for _, node := range nodes {
		switch n := node.(type) {
		case adfText:
			if href := linkHref(n); href != "" {
				fmt.Fprintf(&b, "[%s|%s]", n.Text, href)
			} else {
				b.WriteString(n.Text)
			}
		case adfHardBreak:
			b.WriteString("\n")
		}
	}
	return b.String()
}

func linkHref(t adfText) string {
	for _, m := range t.Marks {
		if m.Type == "link" {
			return strings.TrimSpace(m.Attrs.Href)
		}
	}
	return ""
}

// neutralizeWikiMacros defangs a closing {code} sequence inside evidence
// bodies so scanner-controlled content cannot terminate the code block early
// and inject live wiki markup into the rest of the description.
func neutralizeWikiMacros(s string) string {
	return strings.ReplaceAll(s, "{code", "{ code")
}
