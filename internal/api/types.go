package api

// Shared request/response types for the API
type StoreRequest struct {
    UserID      string `json:"user_id"`
    ServerShare string `json:"server_share"`
    Vault       string `json:"vault"`
    Nonce       string `json:"nonce"`
    Metadata    string `json:"metadata,omitempty"`
}

type VaultResponse struct {
    UserID      string `json:"user_id"`
    ServerShare string `json:"server_share"`
    Vault       string `json:"vault"`
    Nonce       string `json:"nonce"`
    Metadata    string `json:"metadata,omitempty"`
}
