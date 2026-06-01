package storage

import (
	"database/sql"
	"fmt"
	"time"

	// use modernc.org/sqlite (pure-Go)
	_ "modernc.org/sqlite"
)

type ServerStore struct {
	db *sql.DB
}

func NewServerStore(path string) (*ServerStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	s := &ServerStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *ServerStore) migrate() error {
	const schema = `CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY,
    server_share BLOB,
    vault BLOB,
    nonce BLOB,
    metadata TEXT,
    updated_at DATETIME
);`
	_, err := s.db.Exec(schema)
	return err
}

func (s *ServerStore) Close() error {
	return s.db.Close()
}

// SaveVault inserts or updates the vault row for a user.
func (s *ServerStore) SaveVault(userID string, serverShare []byte, vault []byte, nonce []byte, metadata string) error {
	q := `INSERT INTO vaults(user_id, server_share, vault, nonce, metadata, updated_at)
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET
      server_share=excluded.server_share,
      vault=excluded.vault,
      nonce=excluded.nonce,
      metadata=excluded.metadata,
      updated_at=excluded.updated_at;`
	_, err := s.db.Exec(q, userID, serverShare, vault, nonce, metadata, time.Now().UTC())
	return err
}

// GetVault returns serverShare, vault, nonce, metadata for a given user.
func (s *ServerStore) GetVault(userID string) (serverShare []byte, vault []byte, nonce []byte, metadata string, err error) {
	q := `SELECT server_share, vault, nonce, metadata FROM vaults WHERE user_id = ?`
	row := s.db.QueryRow(q, userID)
	var ss, v, n []byte
	var msql sql.NullString
	if err = row.Scan(&ss, &v, &n, &msql); err != nil {
		if err == sql.ErrNoRows {
			err = fmt.Errorf("not found")
		}
		return
	}
	metadata = ""
	if msql.Valid {
		metadata = msql.String
	}
	serverShare = ss
	vault = v
	nonce = n
	return
}
