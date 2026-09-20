package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoadPipelineInputPropagatesParentCancellationToZAP(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := loadPipelineInput(ctx, pipelineInputOptions{ZapURL: server.URL})
		done <- err
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("ZAP request did not start")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled ZAP fetch returned nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation did not stop ZAP fetch")
	}
}
