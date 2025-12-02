package entities

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	neturl "net/url"
	pathpkg "path"
	"regexp"
	"unicode"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

const inlineTrafficSnippetLimit = 2048

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HTTPRequest struct {
	Headers     []Header `json:"headers,omitempty"`
	BodyHash    string   `json:"bodyHash,omitempty"`    // e.g., sha256 of captured body (future)
	BodyBytes   int      `json:"bodyBytes,omitempty"`   // captured/truncated length (future)
	BodySnippet string   `json:"bodySnippet,omitempty"` // optional small snippet for display
	// New: preserve raw header block and original size
	RawHeader      string `json:"rawHeader,omitempty"`
	RawHeaderBytes int    `json:"rawHeaderBytes,omitempty"`
}

type HTTPResponse struct {
	StatusCode  int      `json:"statusCode,omitempty"`
	Headers     []Header `json:"headers,omitempty"`
	BodyHash    string   `json:"bodyHash,omitempty"`
	BodyBytes   int      `json:"bodyBytes,omitempty"`
	BodySnippet string   `json:"bodySnippet,omitempty"` // optional small snippet for display
	// New: preserve raw header block and original size
	RawHeader      string `json:"rawHeader,omitempty"`
	RawHeaderBytes int    `json:"rawHeaderBytes,omitempty"`
}

type Analyst struct {
	Status     string   `json:"status,omitempty"` // open|triaged|fp|accepted|fixed
	Owner      string   `json:"owner,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Notes      string   `json:"notes,omitempty"`
	TicketRefs []string `json:"ticketRefs,omitempty"`
	UpdatedAt  string   `json:"updatedAt,omitempty"` // RFC3339
}

type Taxonomy struct {
	CWEID      int      `json:"cweid,omitempty"`
	CWEURI     string   `json:"cweUri,omitempty"`
	CAPECIDs   []int    `json:"capecIds,omitempty"`
	ATTACK     []string `json:"attack,omitempty"`
	OWASPTop10 []string `json:"owaspTop10,omitempty"`
	NIST80053  []string `json:"nist80053,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

type Remediation struct {
	Summary      string   `json:"summary,omitempty"`
	References   []string `json:"references,omitempty"`
	Guidance     []string `json:"guidance,omitempty"`
	ExampleFixes []string `json:"exampleFixes,omitempty"`
}

// Detection describes where a ZAP alert rule is implemented and how it operates.
// Populated via enrichment (scraped from ZAP docs/GitHub); optional.
type Detection struct {
	LogicType   string             `json:"logicType,omitempty"`   // passive|active|unknown
	PluginRef   string             `json:"pluginRef,omitempty"`   // add-on or rule ref if known
	RuleSource  string             `json:"ruleSource,omitempty"`  // repo-like path within zap-extensions
	DocsURL     string             `json:"docsUrl,omitempty"`     // https://www.zaproxy.org/docs/alerts/{id}/
	SourceURL   string             `json:"sourceUrl,omitempty"`   // GitHub blob URL to the rule class
	MatchReason string             `json:"matchReason,omitempty"` // description of how we derived the mapping
	Summary     string             `json:"summary,omitempty"`     // brief description of how detection works
	Signals     []string           `json:"signals,omitempty"`     // extracted hints like headers/regexes
	Defaults    *DetectionDefaults `json:"defaults,omitempty"`    // threshold/strength, if found
}

type DetectionDefaults struct {
	Threshold string `json:"threshold,omitempty"` // AlertThreshold e.g., MEDIUM
	Strength  string `json:"strength,omitempty"`  // AttackStrength e.g., MEDIUM
}

type Definition struct {
	DefinitionID string       `json:"definitionId"`
	PluginID     string       `json:"pluginId"`
	Alert        string       `json:"alert,omitempty"`
	Name         string       `json:"name,omitempty"`
	WASCID       int          `json:"wascid,omitempty"`
	Taxonomy     *Taxonomy    `json:"taxonomy,omitempty"`
	Remediation  *Remediation `json:"remediation,omitempty"`
	Detection    *Detection   `json:"detection,omitempty"`
}

type Finding struct {
	FindingID    string `json:"findingId"`
	DefinitionID string `json:"definitionId"`
	PluginID     string `json:"pluginId"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	Name         string `json:"name,omitempty"` // human-readable name (e.g., "GET https://example.com/login")
	Risk         string `json:"risk,omitempty"`
	RiskCode     string `json:"riskcode,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
	Occurrences  int    `json:"occurrenceCount"`
}

type Occurrence struct {
	OccurrenceID string `json:"occurrenceId"`
	ScanLabel    string `json:"scanLabel,omitempty"`
	ObservedAt   string `json:"observedAt,omitempty"`
	DefinitionID string `json:"definitionId"`
	FindingID    string `json:"findingId"`

	Name       string `json:"name,omitempty"` // human-readable name (e.g., "GET /login param=user ev=\"...\"")
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Param      string `json:"param,omitempty"`
	Attack     string `json:"attack,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Other      string `json:"other,omitempty"`
	Risk       string `json:"risk,omitempty"`
	RiskCode   string `json:"riskcode,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	SourceID   string `json:"sourceid,omitempty"`

	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
	Analyst  *Analyst      `json:"analyst,omitempty"`
}

type EntitiesFile struct {
	SchemaVersion string       `json:"schemaVersion"`
	GeneratedAt   string       `json:"generatedAt"`
	SourceTool    string       `json:"sourceTool,omitempty"`
	Definitions   []Definition `json:"definitions"`
	Findings      []Finding    `json:"findings"`
	Occurrences   []Occurrence `json:"occurrences"`
}

// BuildOptions controls how entities are constructed for a single scan/import.
// GeneratedAt/ObservedAt should be RFC3339 when provided; when empty they fall
// back to now(). ScanLabel lets us keep scan-level identity per occurrence.
type BuildOptions struct {
	SourceTool  string
	ScanLabel   string
	GeneratedAt string
	ObservedAt  string
}

func shortHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:8])
}

func defID(pluginID string) string {
	return "def-" + strings.TrimSpace(pluginID)
}

func findingKey(a zapclient.Alert) string {
	return strings.Join([]string{
		strings.TrimSpace(a.PluginID),
		strings.TrimSpace(a.URL),
		strings.TrimSpace(a.Method),
	}, "|")
}

// occurrenceKey scopes an alert to a specific scan label so repeated detections
// across different scans remain distinct occurrences.
func occurrenceKey(a zapclient.Alert, scanLabel string) string {
	prefix := zapclient.AlertKey(a)
	sl := strings.TrimSpace(scanLabel)
	if sl == "" {
		return prefix
	}
	return prefix + "|scan:" + sl
}

func splitRefs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func BuildEntities(alerts []zapclient.Alert, sourceTool string) EntitiesFile {
	return BuildEntitiesWithOptions(alerts, BuildOptions{SourceTool: sourceTool})
}

func BuildEntitiesWithOptions(alerts []zapclient.Alert, opts BuildOptions) EntitiesFile {
	genAt := strings.TrimSpace(opts.GeneratedAt)
	if genAt == "" {
		genAt = time.Now().UTC().Format(time.RFC3339)
	}
	obsAt := strings.TrimSpace(opts.ObservedAt)
	if obsAt == "" {
		obsAt = genAt
	}
	sourceTool := strings.TrimSpace(opts.SourceTool)
	if sourceTool == "" {
		sourceTool = "zap"
	}
	defMap := make(map[string]Definition)
	findMap := make(map[string]Finding)
	var occs []Occurrence

	for _, a := range alerts {
		did := defID(a.PluginID)
		if _, ok := defMap[did]; !ok {
			cwe := a.CWEID.Int()
			var tax *Taxonomy
			if cwe > 0 {
				tax = &Taxonomy{
					CWEID:  cwe,
					CWEURI: "https://cwe.mitre.org/data/definitions/" + strings.TrimSpace(strconvItoaSafe(cwe)) + ".html",
				}
			}
			defMap[did] = Definition{
				DefinitionID: did,
				PluginID:     a.PluginID,
				Alert:        a.Alert,
				Name:         a.Name,
				WASCID:       a.WASCID.Int(),
				Taxonomy:     tax,
				Remediation: &Remediation{
					Summary:    strings.TrimSpace(a.Solution),
					References: splitRefs(a.Reference),
				},
			}
		}

		fk := findingKey(a)
		fid := "fin-" + shortHash(fk)
		f, ok := findMap[fid]
		if !ok {
			f = Finding{
				FindingID:    fid,
				DefinitionID: did,
				PluginID:     a.PluginID,
				URL:          a.URL,
				Method:       a.Method,
				Name:         makeFindingName(a),
				Risk:         a.Risk,
				RiskCode:     a.RiskCode,
				Confidence:   a.Confidence,
				Occurrences:  0,
			}
		}
		f.Occurrences++
		findMap[fid] = f

		occ := Occurrence{
			OccurrenceID: "occ-" + shortHash(occurrenceKey(a, opts.ScanLabel)),
			ScanLabel:    opts.ScanLabel,
			ObservedAt:   obsAt,
			DefinitionID: did,
			FindingID:    fid,
			Name:         makeOccurrenceName(a),
			URL:          a.URL,
			Method:       a.Method,
			Param:        a.Param,
			Attack:       a.Attack,
			Evidence:     a.Evidence,
			Other:        a.Other,
			Risk:         a.Risk,
			RiskCode:     a.RiskCode,
			Confidence:   a.Confidence,
			SourceID:     a.SourceID,
			Request:      nil,
			Response:     nil,
			Analyst:      nil,
		}
		attachInlineTrafficFromAlert(&occ, a)
		occs = append(occs, occ)
	}

	// Flatten and stable sort
	defs := make([]Definition, 0, len(defMap))
	for _, d := range defMap {
		defs = append(defs, d)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].PluginID < defs[j].PluginID })

	finds := make([]Finding, 0, len(findMap))
	for _, f := range findMap {
		finds = append(finds, f)
	}
	sort.Slice(finds, func(i, j int) bool {
		if finds[i].PluginID != finds[j].PluginID {
			return finds[i].PluginID < finds[j].PluginID
		}
		if finds[i].URL != finds[j].URL {
			return finds[i].URL < finds[j].URL
		}
		return finds[i].Method < finds[j].Method
	})
	sort.Slice(occs, func(i, j int) bool {
		if occs[i].FindingID != occs[j].FindingID {
			return occs[i].FindingID < occs[j].FindingID
		}
		if occs[i].URL != occs[j].URL {
			return occs[i].URL < occs[j].URL
		}
		if occs[i].Param != occs[j].Param {
			return occs[i].Param < occs[j].Param
		}
		return occs[i].Evidence < occs[j].Evidence
	})

	return EntitiesFile{
		SchemaVersion: "v1",
		GeneratedAt:   genAt,
		SourceTool:    sourceTool,
		Definitions:   defs,
		Findings:      finds,
		Occurrences:   occs,
	}
}

// attachInlineTrafficFromAlert preserves inline request/response snippets that
// arrived with the alert (e.g., flattened traditional-json-plus reports). This
// supplements or pre-populates the traffic blocks without requiring a live ZAP
// instance for enrichment.
func attachInlineTrafficFromAlert(o *Occurrence, a zapclient.Alert) {
	if o == nil {
		return
	}
	reqHeader := strings.TrimSpace(a.RequestHeader)
	reqBody := a.RequestBody
	if reqHeader != "" || strings.TrimSpace(reqBody) != "" {
		o.Request = &HTTPRequest{
			Headers:        parseRawHeaders(a.RequestHeader),
			BodyBytes:      len(reqBody),
			BodySnippet:    truncateUTF8(reqBody, inlineTrafficSnippetLimit),
			RawHeader:      a.RequestHeader,
			RawHeaderBytes: len(a.RequestHeader),
		}
	}

	respHeader := strings.TrimSpace(a.ResponseHeader)
	respBody := a.ResponseBody
	if respHeader != "" || strings.TrimSpace(respBody) != "" {
		headers, status := parseRespHeaders(a.ResponseHeader)
		o.Response = &HTTPResponse{
			StatusCode:     status,
			Headers:        headers,
			BodyBytes:      len(respBody),
			BodySnippet:    truncateUTF8(respBody, inlineTrafficSnippetLimit),
			RawHeader:      a.ResponseHeader,
			RawHeaderBytes: len(a.ResponseHeader),
		}
	}
}

// strconvItoaSafe avoids importing strconv at top just for one call in this file.
func strconvItoaSafe(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return sign + string(buf[i:])
}

// helpers for readable names
func friendlyFindingName(method, url string) string {
	method = strings.TrimSpace(method)
	url = strings.TrimSpace(url)
	if method == "" {
		return url
	}
	if url == "" {
		return method
	}
	return method + " " + url
}

func friendlyOccurrenceName(a zapclient.Alert) string {
	parts := []string{strings.TrimSpace(a.Method), strings.TrimSpace(a.URL)}
	if strings.TrimSpace(a.Param) != "" {
		parts = append(parts, "param="+strings.TrimSpace(a.Param))
	}
	if strings.TrimSpace(a.Evidence) != "" {
		parts = append(parts, `ev="`+truncateStr(strings.TrimSpace(a.Evidence), 40)+`"`)
	}
	return strings.Join(parts, " ")
}

// New naming helpers (rule-centric, no HTTP method)
func makeFindingName(a zapclient.Alert) string {
	rule := firstNonEmpty(a.Alert, a.Name, a.PluginID)
	acro := ruleAcr(rule)
	base, hostRoot := urlBaseOrParent(a.URL)
	name := acro + ": "
	if base != "" {
		name += base
	} else if hostRoot != "" {
		name += hostRoot
	}
	if p := strings.TrimSpace(a.Param); p != "" {
		name += "[" + paramAcronym(p) + "]"
	}
	return ellipsisMiddle(name, 40)
}

func makeOccurrenceName(a zapclient.Alert) string {
	base, hostRoot := urlBaseOrParent(a.URL)
	name := ""
	if base != "" {
		name = base
	} else {
		name = hostRoot
	}
	if p := strings.TrimSpace(a.Param); p != "" {
		name += "[" + paramAcronym(p) + "]"
	}
	return ellipsisMiddle(name, 40)
}

func ruleAcr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "ALRT"
	}
	re := regexp.MustCompile(`[^A-Za-z0-9]+`)
	parts := re.Split(s, -1)
	stop := map[string]struct{}{
		"header": {}, "missing": {}, "not": {}, "set": {}, "detected": {}, "found": {},
		"the": {}, "and": {}, "of": {}, "to": {}, "in": {}, "for": {}, "a": {}, "an": {},
	}
	out := make([]rune, 0, 6)
	for _, p := range parts {
		if p == "" {
			continue
		}
		if _, ok := stop[strings.ToLower(p)]; ok {
			continue
		}
		r := []rune(p)
		out = append(out, unicode.ToUpper(r[0]))
		if len(out) >= 5 {
			break
		}
	}
	if len(out) == 0 {
		return "ALRT"
	}
	return string(out)
}

// Returns basename; if basename looks generic, return parent/basename.
// Also returns host root like example.com/ when path is empty or "/".
func urlBaseOrParent(raw string) (basename string, hostRoot string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		// fallback: last path segment only
		segs := strings.Split(strings.Trim(raw, "/"), "/")
		b := segs[len(segs)-1]
		if b == "" {
			b = "root"
		}
		return b, ""
	}
	if u.Path == "" || u.Path == "/" {
		if u.Host != "" {
			return "", u.Host + "/"
		}
		return "root", ""
	}
	p := u.Path
	b := pathpkg.Base(p)
	if b == "." || b == "/" || b == "" {
		return "root", ""
	}
	// Consider generic filenames as needing parent context
	low := strings.ToLower(b)
	generic := map[string]struct{}{"index.html": {}, "index.htm": {}, "default.aspx": {}, "home": {}}
	if _, ok := generic[low]; ok {
		parent := pathpkg.Base(pathpkg.Dir(p))
		if parent != "." && parent != "/" && parent != "" {
			return parent + "/" + b, ""
		}
	}
	return b, ""
}

func paramAcronym(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	re := regexp.MustCompile(`[^A-Za-z0-9]+`)
	parts := re.Split(s, -1)
	var out []rune
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, unicode.ToLower([]rune(p)[0]))
		if len(out) >= 8 {
			break
		}
	}
	return string(out)
}

func ellipsisMiddle(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// keep start and end
	keep := max - 1 // for the ellipsis char
	head := keep / 2
	tail := keep - head
	return s[:head] + "…" + s[len(s)-tail:]
}

func truncateStr(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
