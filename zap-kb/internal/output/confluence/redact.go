package confluence

import (
	"context"
	"html"
	"regexp"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

type outputPolicyKey struct{}

func withOutputPolicy(ctx context.Context, ro entities.RedactOptions) context.Context {
	return context.WithValue(ctx, outputPolicyKey{}, ro)
}

// Preserve the analyst log's published history and decisions. Only explicitly
// requested free-text cells are omitted; ordinary publishes keep the block.
var analystFreeTextCell = regexp.MustCompile(`(?is)(<tr>\s*<th[^>]*>\s*(?:Observation|Rationale|Next steps|Notes)\s*</th>\s*<td[^>]*>).*?(</td>\s*</tr>)`)
var analystHistoryTable = regexp.MustCompile(`(?is)<table\b[^>]*>.*?</table>`)
var analystHistoryRow = regexp.MustCompile(`(?is)<tr>\s*<th[^>]*>\s*(Published|Risk|Occurrences|Last seen|Jira case|Scan|Decision)\s*</th>\s*<td[^>]*>(.*?)</td>\s*</tr>`)

func redactStoredBody(ctx context.Context, body string) string {
	ro, _ := ctx.Value(outputPolicyKey{}).(entities.RedactOptions)
	if !ro.Enabled() {
		return body
	}
	if ro.Notes {
		if log := extractAnalystLog(body); log != "" {
			// Free-form edits outside the standard cells are notes too. Retain
			// only the log's published history rows and canonical decisions.
			var tables strings.Builder
			for _, table := range analystHistoryTable.FindAllString(log, -1) {
				tables.WriteString("<table><tbody>")
				for _, row := range analystHistoryRow.FindAllStringSubmatch(table, -1) {
					if strings.EqualFold(row[1], "Decision") {
						decision := strings.ToLower(strings.TrimSpace(html.UnescapeString(row[2])))
						switch decision {
						case "open", "triaged", "fp", "accepted", "fixed":
						default:
							continue
						}
					}
					tables.WriteString(row[0])
				}
				tables.WriteString("</tbody></table>")
			}
			body = strings.Replace(body, analystLogStart+log+analystLogEnd, analystLogStart+tables.String()+analystLogEnd, 1)
		}
		body = analystFreeTextCell.ReplaceAllString(body, "${1}[redacted]${2}")
		if note := extractOccurrenceNote(body); note != "" {
			body = strings.ReplaceAll(body, occNoteStart+note+occNoteEnd, occNoteStart+"<p>[redacted]</p>"+occNoteEnd)
		}
	}
	// Only server-preserved blocks need this final pass. Generated content has
	// already passed the entity policy, including the intentional ID exemptions.
	for _, markers := range [][2]string{{analystLogStart, analystLogEnd}, {occNoteStart, occNoteEnd}} {
		start := strings.Index(body, markers[0])
		if start < 0 {
			continue
		}
		start += len(markers[0])
		end := strings.Index(body[start:], markers[1])
		if end < 0 {
			continue
		}
		end += start
		body = body[:start] + redactHTMLFragment(body[start:end], ro) + body[end:]
	}
	return body
}

var htmlPart = regexp.MustCompile(`(?s)<[^>]*>|[^<]+`)
var htmlHref = regexp.MustCompile(`(?i)href="[^"]*"`)

func redactHTMLFragment(s string, ro entities.RedactOptions) string {
	return htmlPart.ReplaceAllStringFunc(s, func(part string) string {
		if strings.HasPrefix(part, "<") {
			return htmlHref.ReplaceAllStringFunc(part, func(attr string) string {
				value := attr[6 : len(attr)-1]
				return attr[:6] + html.EscapeString(entities.RedactText(html.UnescapeString(value), ro)) + `"`
			})
		}
		return html.EscapeString(entities.RedactText(html.UnescapeString(part), ro))
	})
}
