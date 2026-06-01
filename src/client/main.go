package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"tugas4_dzmanager/internal/api"
	"tugas4_dzmanager/internal/crypto"
	"tugas4_dzmanager/internal/storage"
	"tugas4_dzmanager/internal/vault"

	"golang.org/x/term"
)

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytepw), nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func createVault(baseURL, dbDir, userID, metadata string) error {
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}

	// generate master key
	masterKey, err := randomBytes(16)
	if err != nil {
		return err
	}

	// split into 3 shares (2,3)
	shares, err := crypto.SplitSecret(masterKey, 2, 3)
	if err != nil {
		return err
	}
	local := shares[0]
	server := shares[1]
	recovery := shares[2]

	// derive key from master password and encrypt local share (store X||Y)
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		return err
	}
	derived, err := crypto.DeriveKey(pw, salt)
	if err != nil {
		return err
	}
	localPlain := append([]byte{local.X}, local.Y...)
	encLocal, localNonce, err := crypto.EncryptAESGCM(derived, localPlain)
	if err != nil {
		return err
	}

	// create empty vault and encrypt with masterKey
	v := vault.Vault{Entries: []vault.Entry{}}
	vb, _ := json.Marshal(v)
	encVault, vaultNonce, err := crypto.EncryptAESGCM(masterKey, vb)
	if err != nil {
		return err
	}

	// save local store
	cs := storage.NewClientStore(dbDir)
	if err := cs.SaveLocal(userID, encLocal, salt, localNonce, encVault, vaultNonce); err != nil {
		return err
	}

	// upload server share and vault to server
	apiClient := api.NewClientAPI(baseURL)
	serverShareBytes := append([]byte{server.X}, server.Y...)
	if err := apiClient.PostStore(userID, serverShareBytes, encVault, vaultNonce, metadata); err != nil {
		return err
	}

	// show recovery share to user (base64)
	recBytes := append([]byte{recovery.X}, recovery.Y...)
	fmt.Println("Recovery share (store this safely):")
	fmt.Println(base64.StdEncoding.EncodeToString(recBytes))
	return nil
}

func openVault(baseURL, dbDir, userID string) error {
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}

	cs := storage.NewClientStore(dbDir)
	encLocal, salt, localNonce, _, _, err := cs.LoadLocal(userID)
	if err != nil {
		return fmt.Errorf("load local: %w", err)
	}
	derived, err := crypto.DeriveKey(pw, salt)
	if err != nil {
		return err
	}
	localPlain, err := crypto.DecryptAESGCM(derived, localNonce, encLocal)
	if err != nil {
		return fmt.Errorf("decrypt local share: %w", err)
	}
	localX := localPlain[0]
	localY := localPlain[1:]

	apiClient := api.NewClientAPI(baseURL)
	ssBytes, encVault, vaultNonce, _, err := apiClient.GetVault(userID)
	if err != nil {
		return fmt.Errorf("get vault: %w", err)
	}
	serverX := ssBytes[0]
	serverY := ssBytes[1:]

	shares := []crypto.Share{{X: localX, Y: localY}, {X: serverX, Y: serverY}}
	masterKey, err := crypto.CombineShares(shares)
	if err != nil {
		return fmt.Errorf("combine shares: %w", err)
	}

	plainVault, err := crypto.DecryptAESGCM(masterKey, vaultNonce, encVault)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}

	var v vault.Vault
	if err := json.Unmarshal(plainVault, &v); err != nil {
		return fmt.Errorf("unmarshal vault: %w", err)
	}
	fmt.Println("Vault entries:")
	for i, e := range v.Entries {
		fmt.Printf("%d) %s - %s - %s\n", i+1, e.Service, e.Username, e.Password)
	}
	return nil
}

func addEntry(baseURL, dbDir, userID string) error {
	// open vault to get masterKey and vault data
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}

	cs := storage.NewClientStore(dbDir)
	encLocal, salt, localNonce, _, _, err := cs.LoadLocal(userID)
	if err != nil {
		return fmt.Errorf("load local: %w", err)
	}
	derived, err := crypto.DeriveKey(pw, salt)
	if err != nil {
		return err
	}
	localPlain, err := crypto.DecryptAESGCM(derived, localNonce, encLocal)
	if err != nil {
		return fmt.Errorf("decrypt local share: %w", err)
	}
	localX := localPlain[0]
	localY := localPlain[1:]

	apiClient := api.NewClientAPI(baseURL)
	ssBytes, encVault, vaultNonce, _, err := apiClient.GetVault(userID)
	if err != nil {
		return fmt.Errorf("get vault: %w", err)
	}
	serverX := ssBytes[0]
	serverY := ssBytes[1:]

	shares := []crypto.Share{{X: localX, Y: localY}, {X: serverX, Y: serverY}}
	masterKey, err := crypto.CombineShares(shares)
	if err != nil {
		return fmt.Errorf("combine shares: %w", err)
	}

	plainVault, err := crypto.DecryptAESGCM(masterKey, vaultNonce, encVault)
	if err != nil {
		return fmt.Errorf("decrypt vault: %w", err)
	}
	var v vault.Vault
	if err := json.Unmarshal(plainVault, &v); err != nil {
		return fmt.Errorf("unmarshal vault: %w", err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Service name: ")
	service, _ := reader.ReadString('\n')
	service = strings.TrimSpace(service)
	fmt.Print("Username/email: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	fmt.Print("Password (leave empty to auto-generate): ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	if password == "" {
		fmt.Print("Password length (min 8): ")
		var l int
		fmt.Scanf("%d", &l)
		pgen, err := crypto.GeneratePassword(l)
		if err != nil {
			return err
		}
		password = pgen
	}

	entry := vault.Entry{Service: service, Username: username, Password: password}
	v.Entries = append(v.Entries, entry)

	newPlain, _ := json.Marshal(v)
	newEncVault, newVaultNonce, err := crypto.EncryptAESGCM(masterKey, newPlain)
	if err != nil {
		return fmt.Errorf("encrypt updated vault: %w", err)
	}

	// upload and update local backup
	serverShareBytes := ssBytes
	if err := apiClient.PostStore(userID, serverShareBytes, newEncVault, newVaultNonce, ""); err != nil {
		return fmt.Errorf("post store: %w", err)
	}
	if err := cs.SaveLocal(userID, encLocal, salt, localNonce, newEncVault, newVaultNonce); err != nil {
		return fmt.Errorf("save local backup: %w", err)
	}
	fmt.Println("Entry added and vault updated on server and local backup")
	return nil
}

func main() {
	baseURL := flag.String("server", "http://localhost:8080", "server base url")
	dbDir := flag.String("local", "data/client", "local client storage dir")
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Println("usage: client <create|open|add> -user <user>")
		os.Exit(1)
	}
	cmd := flag.Arg(0)
	user := "alice"
	if len(flag.Args()) >= 2 {
		user = flag.Arg(1)
	}
	switch cmd {
	case "create":
		if err := createVault(*baseURL, *dbDir, user, ""); err != nil {
			log.Fatal(err)
		}
	case "open":
		if err := openVault(*baseURL, *dbDir, user); err != nil {
			log.Fatal(err)
		}
	case "add":
		if err := addEntry(*baseURL, *dbDir, user); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Println("unknown command")
	}
}
