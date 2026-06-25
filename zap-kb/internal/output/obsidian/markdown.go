package obsidian

import (
	"fmt"
	"strings"
)

func escapeTable(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return strings.ReplaceAll(s, "|", "\\|")
}

func markdownTableLink(label, target string) string {
	label = escapeTable(label)
	target = escapeTable(target)
	if target == "" {
		return label
	}
	if label == "" {
		label = target
	}
	return fmt.Sprintf("[%s](%s)", label, target)
}
