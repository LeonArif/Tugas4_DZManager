package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"tugas4_dzmanager/internal/crypto"
	"tugas4_dzmanager/internal/storage"
)

// BackupInput groups user-provided inputs for backup mode.
type BackupInput struct {
	UserID          string
	MasterPassword  string
	RecoveryShare64 string
}

// DecodeShareBase64 should parse a base64-encoded recovery share
// into a crypto.Share (X byte + Y bytes).
func DecodeShareBase64(share64 string) (crypto.Share, error) {
	if share64 == "" {
		return crypto.Share{}, errors.New("empty recovery share")
	}
	raw, err := base64.StdEncoding.DecodeString(share64)
	if err != nil {
		return crypto.Share{}, fmt.Errorf("decode share: %w", err)
	}
	if len(raw) < 2 {
		return crypto.Share{}, errors.New("share data too short")
	}
	return crypto.Share{X: raw[0], Y: raw[1:]}, nil
}

// OpenBackupVault should open the backup vault using local share + recovery share.
// Flow (to implement):
// 1) Load local encrypted share + backup vault from client store
// 2) Derive key from MasterPassword, decrypt local share
// 3) Parse recovery share (base64 -> Share)
// 4) Combine shares to reconstruct master key
// 5) Decrypt backup vault and unmarshal into Vault
func OpenBackupVault(store *storage.ClientStore, in BackupInput) (*Vault, error) {
	if store == nil {
		return nil, errors.New("client store is nil")
	}
	if in.UserID == "" {
		return nil, errors.New("user id is required")
	}
	if in.MasterPassword == "" {
		return nil, errors.New("master password is required")
	}
	encLocal, salt, localNonce, backupVault, backupNonce, err := store.LoadLocal(in.UserID)
	if err != nil {
		return nil, fmt.Errorf("load local: %w", err)
	}
	derived, err := crypto.DeriveKey(in.MasterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	localPlain, err := crypto.DecryptAESGCM(derived, localNonce, encLocal)
	if err != nil {
		return nil, fmt.Errorf("decrypt local share: %w", err)
	}
	if len(localPlain) < 2 {
		return nil, errors.New("local share is invalid")
	}
	localShare := crypto.Share{X: localPlain[0], Y: localPlain[1:]}
	backupShare, err := DecodeShareBase64(in.RecoveryShare64)
	if err != nil {
		return nil, err
	}
	masterKey, err := crypto.CombineShares([]crypto.Share{localShare, backupShare})
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}
	plainVault, err := crypto.DecryptAESGCM(masterKey, backupNonce, backupVault)
	if err != nil {
		return nil, fmt.Errorf("decrypt backup vault: %w", err)
	}
	var v Vault
	if err := json.Unmarshal(plainVault, &v); err != nil {
		return nil, fmt.Errorf("unmarshal vault: %w", err)
	}
	return &v, nil
}
