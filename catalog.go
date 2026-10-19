package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

var catalogCandidates struct {
	sync.RWMutex
	Models []json.RawMessage
}

// Only the host-authenticated principal is authoritative. Never infer identity
// from candidate credentials supplied in headers or query parameters.
func catalogScopes(req responseInterceptRequest) []string {
	if scope, ok := callerScopeFromMetadata(req.Metadata); ok {
		return []string{scope}
	}
	return nil
}

func catalogModelID(raw json.RawMessage) string {
	var item struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &item) != nil {
		return ""
	}
	if item.ID != "" {
		return item.ID
	}
	if item.Slug != "" {
		return item.Slug
	}
	return strings.TrimPrefix(item.Name, "models/")
}

func catalogModelAllowed(snapshot policySnapshot, scopes []string, id string) bool {
	if snapshot.BlockAll || len(scopes) == 0 || id == "" {
		return false
	}
	identities := []string{id}
	// The reserved prewarm registration prefix encodes an existing account route.
	// Keep arbitrary vendor/model IDs intact. Runtime still checks CPA's resolved ID.
	if strings.HasPrefix(strings.ToLower(id), "warmup-") {
		if split := strings.IndexByte(id, '/'); split > len("warmup-") {
			identities = append(identities, id[split+1:])
		}
	}
	if globalDeniedRule(snapshot, identities...) != "" {
		return false
	}
	for _, scope := range scopes {
		if policy, ok := snapshot.ByCallerScope[scope]; ok && !policyAllows(policy, id) {
			return false
		}
	}
	return true
}

func filterCatalog(raw []byte) ([]byte, error) {
	var req responseInterceptRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	if req.Model != "" || req.RequestedModel != "" || req.Stream || req.StatusCode != 200 {
		return okEnvelope(responseInterceptResponse{})
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(req.Body, &document) != nil {
		return okEnvelope(responseInterceptResponse{})
	}
	field := "data"
	if _, ok := document[field]; !ok {
		field = "models"
	}
	var entries []json.RawMessage
	if data, ok := document[field]; !ok || json.Unmarshal(data, &entries) != nil {
		return okEnvelope(responseInterceptResponse{})
	}
	if field == "data" && req.SourceFormat == "openai" {
		// Keep a single complete snapshot, not a union: removed models disappear too.
		catalogCandidates.Lock()
		catalogCandidates.Models = append([]json.RawMessage{}, entries...)
		catalogCandidates.Unlock()
	}
	_, snapshot, _, _, _, _ := globalState.current()
	scopes := catalogScopes(req)
	filtered := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		if catalogModelAllowed(snapshot, scopes, catalogModelID(entry)) {
			filtered = append(filtered, entry)
		}
	}
	document[field], _ = json.Marshal(filtered)
	// Anthropic pagination must not advertise removed entries.
	if _, ok := document["has_more"]; ok {
		document["has_more"] = json.RawMessage("false")
	}
	for _, key := range []string{"first_id", "last_id"} {
		if _, ok := document[key]; ok {
			value := ""
			if len(filtered) > 0 {
				index := 0
				if key == "last_id" {
					index = len(filtered) - 1
				}
				value = catalogModelID(filtered[index])
			}
			document[key], _ = json.Marshal(value)
		}
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return okEnvelope(responseInterceptResponse{Body: body, Headers: http.Header{"Cache-Control": []string{"private, no-store"}, "Vary": []string{"Authorization, X-Api-Key, X-Goog-Api-Key"}}, ClearHeaders: []string{"Content-Length", "ETag"}})
}

func managementCatalog() ([]byte, error) {
	catalogCandidates.RLock()
	models := append([]json.RawMessage{}, catalogCandidates.Models...)
	catalogCandidates.RUnlock()
	return managementJSON(http.StatusOK, map[string]any{"data": models})
}
