package forgejo

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWikiReusesPathsAndReadsCurrentRemoteContent(t *testing.T) {
	vault, names, files := scaleVault(t, 4)
	remote := newScaleWiki()
	srv := httptest.NewServer(remote)
	defer srv.Close()
	opts := WikiOptions{BaseURL: srv.URL, Token: "synthetic", Owner: "scale", Repo: "disposable", RequestDelay: time.Nanosecond}
	if sum, err := ExportWiki(context.Background(), vault, opts); err != nil || sum.Errors != 0 {
		t.Fatalf("initial publish: %+v %v", sum, err)
	}
	remote.verify(t, names, files)
	remote.reset()
	// An out-of-band content change must be detected even though the page
	// was previously published. No local manifest can hide it.
	remote.mu.Lock()
	p := remote.pages[names[1]]
	p.Content = "external content edit"
	remote.pages[p.Title] = p
	remote.mu.Unlock()
	sum, err := ExportWiki(context.Background(), vault, opts)
	if err != nil || sum.Updated != 1 || sum.Skipped != 3 || sum.Errors != 0 {
		t.Fatalf("remote change: %+v %v", sum, err)
	}
	remote.verify(t, names, files)
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if len(remote.requests["GET list"]) != 2 || len(remote.requests["GET page"]) != 4 || remote.mutations != 1 {
		t.Fatalf("want one listing traversal, every page read, one mutation; requests=%v mutations=%d", remote.requests, remote.mutations)
	}
}

func TestWikiConcurrentRenameFallsBackAndNextRunConverges(t *testing.T) {
	vault, names, files := scaleVault(t, 3)
	remote := newScaleWiki()
	srv := httptest.NewServer(remote)
	defer srv.Close()
	opts := WikiOptions{BaseURL: srv.URL, Token: "synthetic", Owner: "scale", Repo: "disposable", RequestDelay: time.Nanosecond, Concurrency: 1}
	if sum, err := ExportWiki(context.Background(), vault, opts); err != nil || sum.Errors != 0 {
		t.Fatalf("initial publish: %+v %v", sum, err)
	}
	remote.reset()
	// The title disappears after listing but before its GET. Simulate an
	// analyst rename to a non-KB page, which a later run must preserve.
	remote.mu.Lock()
	remote.beforeRead = func(s *scaleWiki, sub string) {
		if sub != scaleSubURL(names[1]) {
			return
		}
		p := s.pages[names[1]]
		delete(s.pages, names[1])
		p.Title, p.SubURL = "Analyst Notes", "Analyst-Notes"
		s.pages[p.Title] = p
		s.beforeRead = nil
	}
	remote.mu.Unlock()
	sum, err := ExportWiki(context.Background(), vault, opts)
	if err == nil && sum.Errors == 0 {
		t.Fatal("concurrent disappearance incorrectly reported success")
	}
	remote.mu.Lock()
	if len(remote.requests["GET list"]) != 4 {
		t.Errorf("error must retain second traversal: %v", remote.requests)
	}
	remote.mu.Unlock()
	if sum, err = ExportWiki(context.Background(), vault, opts); err != nil || sum.Errors != 0 || sum.Created != 1 {
		t.Fatalf("recovery: %+v %v", sum, err)
	}
	remote.verify(t, names, files)
	remote.mu.Lock()
	if !strings.Contains(remote.pages["Analyst Notes"].Content, "Synthetic evidence") {
		t.Error("renamed analyst page was not preserved")
	}
	remote.mu.Unlock()
	remote.reset()
	if sum, err = ExportWiki(context.Background(), vault, opts); err != nil || sum.Errors != 0 || sum.Skipped != 3 {
		t.Fatalf("recovered noop: %+v %v", sum, err)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.mutations != 0 {
		t.Fatalf("recovered noop mutated %d pages", remote.mutations)
	}
}
