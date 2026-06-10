// Package deploypolicy statically validates the shipped Kubernetes manifests
// under deploy/k8s against the project's resolved sync-layer semantics. It is
// intentionally untagged so it runs in every `go test ./...` — manifest
// regressions fail PRs without needing a cluster.
package deploypolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const k8sDir = "../../../../deploy/k8s"

// loadDocs parses every YAML document in every manifest under deploy/k8s.
// Commented-out hook manifests (40-*, 41-*) may yield zero documents — that's
// fine; what matters is that nothing fails to parse.
func loadDocs(t *testing.T) map[string][]map[string]any {
	t.Helper()
	entries, err := os.ReadDir(k8sDir)
	if err != nil {
		t.Fatalf("deploy/k8s not found relative to test (%s): %v", k8sDir, err)
	}
	out := make(map[string][]map[string]any)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(k8sDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		for {
			var doc map[string]any
			err := dec.Decode(&doc)
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				if strings.Contains(err.Error(), "EOF") {
					break
				}
				t.Fatalf("%s: invalid YAML: %v", e.Name(), err)
			}
			if doc != nil {
				out[e.Name()] = append(out[e.Name()], doc)
			}
		}
	}
	return out
}

// findCronJob returns the kb-publisher CronJob document.
func findCronJob(t *testing.T, docs map[string][]map[string]any) map[string]any {
	t.Helper()
	for _, ds := range docs {
		for _, d := range ds {
			if d["kind"] == "CronJob" {
				if meta, _ := d["metadata"].(map[string]any); meta != nil && meta["name"] == "kb-publisher" {
					return d
				}
			}
		}
	}
	t.Fatal("kb-publisher CronJob not found in deploy/k8s")
	return nil
}

// dig walks nested map keys.
func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

// publisherContainer returns the publisher container spec from the CronJob.
func publisherContainer(t *testing.T, cj map[string]any) map[string]any {
	t.Helper()
	containers, _ := dig(cj, "spec", "jobTemplate", "spec", "template", "spec", "containers").([]any)
	if len(containers) == 0 {
		t.Fatal("CronJob has no containers")
	}
	c, _ := containers[0].(map[string]any)
	if c == nil {
		t.Fatal("container spec malformed")
	}
	return c
}

func containerArgs(c map[string]any) []string {
	raw, _ := c["args"].([]any)
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		out = append(out, fmt.Sprintf("%v", a))
	}
	return out
}

// Resolved semantics #1: ticket workflow state lives in Forgejo (external
// source of truth) and is never round-tripped into the KB. The shipped
// CronJob must not enable the write-back flag.
func TestCronJobDoesNotRoundTripTicketState(t *testing.T) {
	cj := findCronJob(t, loadDocs(t))
	for _, arg := range containerArgs(publisherContainer(t, cj)) {
		if strings.Contains(arg, "-forgejo-sync-kb-status") {
			t.Fatalf("R2 VIOLATED: shipped CronJob passes %q — ticket state must not round-trip into the KB", arg)
		}
	}
}

// R4/A19: the API token must reach the publisher via the secret (envFrom),
// never as a command-line argument (argv is visible in pod specs and `ps`).
func TestCronJobTokenComesFromSecretNotArgv(t *testing.T) {
	cj := findCronJob(t, loadDocs(t))
	c := publisherContainer(t, cj)
	for _, arg := range containerArgs(c) {
		if strings.Contains(arg, "-forgejo-token") {
			t.Fatalf("R4 VIOLATED: token passed via argv: %q", arg)
		}
	}
	found := false
	if envFrom, _ := c["envFrom"].([]any); envFrom != nil {
		for _, ef := range envFrom {
			if m, _ := ef.(map[string]any); m != nil {
				if sr, _ := m["secretRef"].(map[string]any); sr != nil && sr["name"] == "forgejo-credentials" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("CronJob does not mount the forgejo-credentials secret via envFrom")
	}
}

// Defense-in-depth posture of the publisher pod.
func TestCronJobSecurityAndScheduling(t *testing.T) {
	cj := findCronJob(t, loadDocs(t))

	if v, _ := dig(cj, "spec", "concurrencyPolicy").(string); v != "Forbid" {
		t.Errorf("concurrencyPolicy = %q, want Forbid (two overlapping scheduled publishers race the dedup index — assumption A11)", v)
	}
	if v, ok := dig(cj, "spec", "jobTemplate", "spec", "template", "spec", "securityContext", "runAsNonRoot").(bool); !ok || !v {
		t.Errorf("publisher pod must set securityContext.runAsNonRoot: true")
	}

	// The ingest volume is the integration seam for detection sources — the
	// publisher must mount the kb-ingest PVC.
	vols, _ := dig(cj, "spec", "jobTemplate", "spec", "template", "spec", "volumes").([]any)
	foundIngest := false
	for _, v := range vols {
		if m, _ := v.(map[string]any); m != nil {
			if pvc, _ := m["persistentVolumeClaim"].(map[string]any); pvc != nil && pvc["claimName"] == "kb-ingest" {
				foundIngest = true
			}
		}
	}
	if !foundIngest {
		t.Errorf("publisher CronJob does not mount the kb-ingest PVC (the detection-source ingest seam)")
	}
}

// Every manifest must at least parse — catches broken YAML before kubectl does.
func TestAllManifestsParse(t *testing.T) {
	docs := loadDocs(t)
	if len(docs) == 0 {
		t.Fatal("no manifests parsed from deploy/k8s")
	}
}
