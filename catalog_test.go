package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCatalogPreservesMetadataAndFiltersEachKey(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 3, GlobalDenyModels: []string{"blocked"}, Policies: []policyConfig{{CallerScope: scopeA, DenyModels: []string{"warmup-*/*"}}}})
	for _, field := range []string{"data", "models"} {
		idField := "id"
		if field == "models" {
			idField = "slug"
		}
		body := `{"extra":{"keep":true},"` + field + `":[{"` + idField + `":"ok","context_window":123456,"custom":{"a":1}},{"` + idField + `":"blocked"},{"` + idField + `":"warmup-account/ok"},{"` + idField + `":"warmup-account/blocked"}]}`
		for key, want := range map[string]int{"secret-a": 1, "secret-b": 2} {
			raw, _ := json.Marshal(responseInterceptRequest{SourceFormat: "openai", StatusCode: 200, Body: []byte(body), Metadata: map[string]any{"caller_scope": callerScope(key)}, RequestHeaders: http.Header{"Authorization": []string{"Bearer " + key}}})
			out, err := filterCatalog(raw)
			if err != nil {
				t.Fatal(err)
			}
			var response responseInterceptResponse
			unwrapEnvelope(t, out, &response)
			var got map[string]json.RawMessage
			json.Unmarshal(response.Body, &got)
			var entries []json.RawMessage
			json.Unmarshal(got[field], &entries)
			if len(entries) != want || !strings.Contains(string(got["extra"]), "keep") || !strings.Contains(string(entries[0]), "123456") {
				t.Fatalf("metadata or filtering error: %s", response.Body)
			}
		}
	}
}
func TestCatalogIdentityCannotBeSpoofedAndMissingFailsClosed(t *testing.T) {
	snap, _, _ := compileDocument(policyDocument{Version: 3, Policies: []policyConfig{{CallerScope: scopeA, DenyModels: []string{"private"}}}})
	req := responseInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA}, RequestHeaders: http.Header{"Authorization": []string{"Bearer fake"}, "X-Api-Key": []string{"secret-a"}}}
	if catalogModelAllowed(snap, catalogScopes(req), "private") {
		t.Fatal("extra auth header loosened policy")
	}
	req.Metadata = nil
	if len(catalogScopes(req)) != 0 {
		t.Fatal("untrusted headers accepted")
	}
	if catalogModelAllowed(snap, nil, "ok") {
		t.Fatal("unknown identity exposed catalog")
	}
	if !catalogModelAllowed(snap, []string{scopeB}, "private") {
		t.Fatal("default key unexpectedly denied")
	}
	snap.BlockAll = true
	if catalogModelAllowed(snap, []string{scopeB}, "private") {
		t.Fatal("fail-closed state exposed catalog")
	}
}
func TestCatalogLeavesGenerationResponsesUntouched(t *testing.T) {
	for _, req := range []responseInterceptRequest{{StatusCode: 200, Model: "x", Body: []byte(`{"data":[{"id":"x"}]}`)}, {SourceFormat: "openai", StatusCode: 200, Body: []byte(`{"output":"hello"}`)}} {
		raw, _ := json.Marshal(req)
		out, err := filterCatalog(raw)
		if err != nil {
			t.Fatal(err)
		}
		var response responseInterceptResponse
		unwrapEnvelope(t, out, &response)
		if len(response.Body) > 0 {
			t.Fatal("generation body modified")
		}
	}
}
