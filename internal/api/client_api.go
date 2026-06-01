package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ClientAPI struct {
	BaseURL string
	Client  *http.Client
}

func NewClientAPI(baseURL string) *ClientAPI {
	return &ClientAPI{BaseURL: strings.TrimRight(baseURL, "/"), Client: &http.Client{}}
}

// use api.StoreRequest

// PostStore uploads server share, vault blob and nonce to server
func (c *ClientAPI) PostStore(userID string, serverShare []byte, vault []byte, nonce []byte, metadata string) error {
	req := StoreRequest{
		UserID:      userID,
		ServerShare: base64.StdEncoding.EncodeToString(serverShare),
		Vault:       base64.StdEncoding.EncodeToString(vault),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Metadata:    metadata,
	}
	b, _ := json.Marshal(req)
	resp, err := c.Client.Post(c.BaseURL+"/store", "application/json", strings.NewReader(string(b)))
	if err != nil {
		return fmt.Errorf("post store: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}
	return nil
}

// use api.VaultResponse

// GetVault retrieves vault data from server
func (c *ClientAPI) GetVault(userID string) (serverShare []byte, vault []byte, nonce []byte, metadata string, err error) {
	resp, err := c.Client.Get(c.BaseURL + "/vault?user_id=" + userID)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("get vault: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, nil, nil, "", fmt.Errorf("server error: %s", string(b))
	}
	var r VaultResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, nil, nil, "", fmt.Errorf("decode response: %w", err)
	}
	ss, err := base64.StdEncoding.DecodeString(r.ServerShare)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("decode server share: %w", err)
	}
	v, err := base64.StdEncoding.DecodeString(r.Vault)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("decode vault: %w", err)
	}
	n, err := base64.StdEncoding.DecodeString(r.Nonce)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("decode nonce: %w", err)
	}
	return ss, v, n, r.Metadata, nil
}
