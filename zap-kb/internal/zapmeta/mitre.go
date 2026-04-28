package zapmeta

import (
	"fmt"
	"strings"
)

// MITRERef is a small, curated offline reference to MITRE-maintained catalogs.
// It intentionally stores titles and canonical URLs only; live catalog adapters
// can replace or extend this later without changing the entity schema.
type MITRERef struct {
	ID     string
	Name   string
	URL    string
	Source string
}

func CWEURL(id int) string {
	if id <= 0 {
		return ""
	}
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", id)
}

func CAPECURL(id int) string {
	if id <= 0 {
		return ""
	}
	return fmt.Sprintf("https://capec.mitre.org/data/definitions/%d.html", id)
}

func ATTACKURL(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return ""
	}
	id = strings.ReplaceAll(id, ".", "/")
	return fmt.Sprintf("https://attack.mitre.org/techniques/%s/", id)
}

func LookupCWEInfo(id int) *MITRERef {
	name, ok := cweNames[id]
	if !ok {
		if id <= 0 {
			return nil
		}
		name = fmt.Sprintf("CWE-%d", id)
	}
	return &MITRERef{
		ID:     fmt.Sprintf("CWE-%d", id),
		Name:   name,
		URL:    CWEURL(id),
		Source: "MITRE CWE",
	}
}

func LookupCAPECInfo(id int) *MITRERef {
	name, ok := capecNames[id]
	if !ok {
		if id <= 0 {
			return nil
		}
		name = fmt.Sprintf("CAPEC-%d", id)
	}
	return &MITRERef{
		ID:     fmt.Sprintf("CAPEC-%d", id),
		Name:   name,
		URL:    CAPECURL(id),
		Source: "MITRE CAPEC",
	}
}

func LookupATTACKInfo(id string) *MITRERef {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return nil
	}
	name, ok := attackNames[id]
	if !ok {
		name = id
	}
	return &MITRERef{
		ID:     id,
		Name:   name,
		URL:    ATTACKURL(id),
		Source: "MITRE ATT&CK",
	}
}

var cweNames = map[int]string{
	22:   "Improper Limitation of a Pathname to a Restricted Directory",
	79:   "Improper Neutralization of Input During Web Page Generation",
	89:   "Improper Neutralization of Special Elements used in an SQL Command",
	200:  "Exposure of Sensitive Information to an Unauthorized Actor",
	209:  "Generation of Error Message Containing Sensitive Information",
	264:  "Permissions, Privileges, and Access Controls",
	287:  "Improper Authentication",
	311:  "Missing Encryption of Sensitive Data",
	312:  "Cleartext Storage of Sensitive Information",
	319:  "Cleartext Transmission of Sensitive Information",
	327:  "Use of a Broken or Risky Cryptographic Algorithm",
	345:  "Insufficient Verification of Data Authenticity",
	502:  "Deserialization of Untrusted Data",
	525:  "Use of Web Browser Cache Containing Sensitive Information",
	549:  "Missing Password Field Masking",
	565:  "Reliance on Cookies without Validation and Integrity Checking",
	614:  "Sensitive Cookie in HTTPS Session Without Secure Attribute",
	639:  "Authorization Bypass Through User-Controlled Key",
	693:  "Protection Mechanism Failure",
	829:  "Inclusion of Functionality from Untrusted Control Sphere",
	918:  "Server-Side Request Forgery",
	942:  "Permissive Cross-domain Policy with Untrusted Domains",
	1004: "Sensitive Cookie Without 'HttpOnly' Flag",
	1021: "Improper Restriction of Rendered UI Layers or Frames",
	1275: "Sensitive Cookie with Improper SameSite Attribute",
}

var capecNames = map[int]string{
	1:   "Accessing Functionality Not Properly Constrained by ACLs",
	37:  "Retrieve Embedded Sensitive Data",
	66:  "SQL Injection",
	86:  "Cross-site Scripting",
	118: "Data Leakage Attacks",
	122: "Privilege Abuse",
}

var attackNames = map[string]string{
	"T1078": "Valid Accounts",
	"T1190": "Exploit Public-Facing Application",
}
