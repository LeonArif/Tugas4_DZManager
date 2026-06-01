package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"tugas4_dzmanager/internal/storage"
)

type Server struct {
	store *storage.ServerStore
}

func NewServer(store *storage.ServerStore) *Server {
	return &Server{store: store}
}

// uses StoreRequest and VaultResponse from types.go

func (s *Server) Router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/store", s.handleStore)
	mux.HandleFunc("/vault", s.handleGetVault)
	return mux
}

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return
	}
	ss, err := base64.StdEncoding.DecodeString(req.ServerShare)
	if err != nil {
		http.Error(w, "invalid server_share: "+err.Error(), http.StatusBadRequest)
		return
	}
	v, err := base64.StdEncoding.DecodeString(req.Vault)
	if err != nil {
		http.Error(w, "invalid vault: "+err.Error(), http.StatusBadRequest)
		return
	}
	n, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		http.Error(w, "invalid nonce: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.store.SaveVault(req.UserID, ss, v, n, req.Metadata); err != nil {
		http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetVault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := r.URL.Query().Get("user_id")
	if user == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return
	}
	ss, v, n, metadata, err := s.store.GetVault(user)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp := VaultResponse{
		UserID:      user,
		ServerShare: base64.StdEncoding.EncodeToString(ss),
		Vault:       base64.StdEncoding.EncodeToString(v),
		Nonce:       base64.StdEncoding.EncodeToString(n),
		Metadata:    metadata,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
		return
	}
}
