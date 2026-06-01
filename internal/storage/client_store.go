package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ClientStore struct {
	Dir string
}

func NewClientStore(dir string) *ClientStore {
	os.MkdirAll(dir, 0o755)
	return &ClientStore{Dir: dir}
}

type clientFile struct {
	EncryptedLocalShare string `json:"encrypted_local_share"` // base64 of (X||Y) encrypted
	Salt                string `json:"salt"`                  // base64
	LocalNonce          string `json:"local_nonce"`           // base64
	BackupVault         string `json:"backup_vault"`          // base64
	BackupNonce         string `json:"backup_nonce"`          // base64
}

func (cs *ClientStore) pathFor(userID string) string {
	return filepath.Join(cs.Dir, userID+".json")
}

func (cs *ClientStore) SaveLocal(userID string, encryptedLocalShare []byte, salt []byte, localNonce []byte, backupVault []byte, backupNonce []byte) error {
	cf := clientFile{
		EncryptedLocalShare: base64.StdEncoding.EncodeToString(encryptedLocalShare),
		Salt:                base64.StdEncoding.EncodeToString(salt),
		LocalNonce:          base64.StdEncoding.EncodeToString(localNonce),
		BackupVault:         base64.StdEncoding.EncodeToString(backupVault),
		BackupNonce:         base64.StdEncoding.EncodeToString(backupNonce),
	}
	b, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal client file: %w", err)
	}
	if err := os.WriteFile(cs.pathFor(userID), b, 0o600); err != nil {
		return fmt.Errorf("write client file: %w", err)
	}
	return nil
}

func (cs *ClientStore) LoadLocal(userID string) (encryptedLocalShare []byte, salt []byte, localNonce []byte, backupVault []byte, backupNonce []byte, err error) {
	data, err := os.ReadFile(cs.pathFor(userID))
	if err != nil {
		return
	}
	var cf clientFile
	if err = json.Unmarshal(data, &cf); err != nil {
		return
	}
	if encryptedLocalShare, err = base64.StdEncoding.DecodeString(cf.EncryptedLocalShare); err != nil {
		return
	}
	if salt, err = base64.StdEncoding.DecodeString(cf.Salt); err != nil {
		return
	}
	if localNonce, err = base64.StdEncoding.DecodeString(cf.LocalNonce); err != nil {
		return
	}
	if backupVault, err = base64.StdEncoding.DecodeString(cf.BackupVault); err != nil {
		return
	}
	if backupNonce, err = base64.StdEncoding.DecodeString(cf.BackupNonce); err != nil {
		return
	}
	return
}
