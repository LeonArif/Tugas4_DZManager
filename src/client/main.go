package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tugas4_dzmanager/internal/api"
	"tugas4_dzmanager/internal/crypto"
	"tugas4_dzmanager/internal/storage"
	"tugas4_dzmanager/internal/vault"
	"tugas4_dzmanager/internal/visual"

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

func readLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

type vaultContext struct {
	cs          *storage.ClientStore
	encLocal    []byte
	salt        []byte
	localNonce  []byte
	serverShare []byte
	masterKey   []byte
	v           vault.Vault
}

func loadVaultContext(baseURL, dbDir, userID, pw string) (*vaultContext, error) {
	cs := storage.NewClientStore(dbDir)
	encLocal, salt, localNonce, _, _, err := cs.LoadLocal(userID)
	if err != nil {
		return nil, fmt.Errorf("load local: %w", err)
	}
	derived, err := crypto.DeriveKey(pw, salt)
	if err != nil {
		return nil, err
	}
	localPlain, err := crypto.DecryptAESGCM(derived, localNonce, encLocal)
	if err != nil {
		return nil, fmt.Errorf("decrypt local share: %w", err)
	}
	if len(localPlain) < 2 {
		return nil, errors.New("local share invalid")
	}
	localX := localPlain[0]
	localY := localPlain[1:]

	apiClient := api.NewClientAPI(baseURL)
	ssBytes, encVault, vaultNonce, _, err := apiClient.GetVault(userID)
	if err != nil {
		return nil, fmt.Errorf("get vault: %w", err)
	}
	if len(ssBytes) < 2 {
		return nil, errors.New("server share invalid")
	}
	serverX := ssBytes[0]
	serverY := ssBytes[1:]

	shares := []crypto.Share{{X: localX, Y: localY}, {X: serverX, Y: serverY}}
	masterKey, err := crypto.CombineShares(shares)
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}

	plainVault, err := crypto.DecryptAESGCM(masterKey, vaultNonce, encVault)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}
	var v vault.Vault
	if err := json.Unmarshal(plainVault, &v); err != nil {
		return nil, fmt.Errorf("unmarshal vault: %w", err)
	}
	return &vaultContext{
		cs:          cs,
		encLocal:    encLocal,
		salt:        salt,
		localNonce:  localNonce,
		serverShare: ssBytes,
		masterKey:   masterKey,
		v:           v,
	}, nil
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
	ctx, err := loadVaultContext(baseURL, dbDir, userID, pw)
	if err != nil {
		return err
	}
	if len(ctx.v.Entries) == 0 {
		fmt.Println("Vault entries: (empty)")
		return nil
	}
	fmt.Println("Vault entries:")
	for i, e := range ctx.v.Entries {
		fmt.Printf("%d) %s - %s - %s\n", i+1, e.Service, e.Username, e.Password)
		if e.Notes != "" {
			fmt.Printf("    notes: %s\n", e.Notes)
		}
	}
	return nil
}

func addEntry(baseURL, dbDir, userID string) error {
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	ctx, err := loadVaultContext(baseURL, dbDir, userID, pw)
	if err != nil {
		return err
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
	ctx.v.Entries = append(ctx.v.Entries, entry)

	newPlain, _ := json.Marshal(ctx.v)
	newEncVault, newVaultNonce, err := crypto.EncryptAESGCM(ctx.masterKey, newPlain)
	if err != nil {
		return fmt.Errorf("encrypt updated vault: %w", err)
	}

	// upload and update local backup
	apiClient := api.NewClientAPI(baseURL)
	if err := apiClient.PostStore(userID, ctx.serverShare, newEncVault, newVaultNonce, ""); err != nil {
		return fmt.Errorf("post store: %w", err)
	}
	if err := ctx.cs.SaveLocal(userID, ctx.encLocal, ctx.salt, ctx.localNonce, newEncVault, newVaultNonce); err != nil {
		return fmt.Errorf("save local backup: %w", err)
	}
	fmt.Println("Entry added and vault updated on server and local backup")
	return nil
}

func editEntry(baseURL, dbDir, userID string) error {
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	ctx, err := loadVaultContext(baseURL, dbDir, userID, pw)
	if err != nil {
		return err
	}
	if len(ctx.v.Entries) == 0 {
		return errors.New("vault is empty")
	}
	for i, e := range ctx.v.Entries {
		fmt.Printf("%d) %s - %s\n", i+1, e.Service, e.Username)
	}
	idxStr := readLine("Entry number to edit: ")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 1 || idx > len(ctx.v.Entries) {
		return errors.New("invalid entry number")
	}
	entry := ctx.v.Entries[idx-1]

	service := readLine(fmt.Sprintf("Service name [%s]: ", entry.Service))
	if service != "" {
		entry.Service = service
	}
	username := readLine(fmt.Sprintf("Username/email [%s]: ", entry.Username))
	if username != "" {
		entry.Username = username
	}
	password := readLine("Password (empty = keep, '-' = auto): ")
	if password == "-" {
		lenStr := readLine("Password length (min 8): ")
		l, err := strconv.Atoi(lenStr)
		if err != nil {
			return fmt.Errorf("invalid length")
		}
		pgen, err := crypto.GeneratePassword(l)
		if err != nil {
			return err
		}
		entry.Password = pgen
	} else if password != "" {
		entry.Password = password
	}
	notes := readLine(fmt.Sprintf("Notes [%s]: ", entry.Notes))
	if notes != "" {
		entry.Notes = notes
	}

	ctx.v.Entries[idx-1] = entry
	newPlain, _ := json.Marshal(ctx.v)
	newEncVault, newVaultNonce, err := crypto.EncryptAESGCM(ctx.masterKey, newPlain)
	if err != nil {
		return fmt.Errorf("encrypt updated vault: %w", err)
	}
	apiClient := api.NewClientAPI(baseURL)
	if err := apiClient.PostStore(userID, ctx.serverShare, newEncVault, newVaultNonce, ""); err != nil {
		return fmt.Errorf("post store: %w", err)
	}
	if err := ctx.cs.SaveLocal(userID, ctx.encLocal, ctx.salt, ctx.localNonce, newEncVault, newVaultNonce); err != nil {
		return fmt.Errorf("save local backup: %w", err)
	}
	fmt.Println("Entry updated and vault saved")
	return nil
}

func deleteEntry(baseURL, dbDir, userID string) error {
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	ctx, err := loadVaultContext(baseURL, dbDir, userID, pw)
	if err != nil {
		return err
	}
	if len(ctx.v.Entries) == 0 {
		return errors.New("vault is empty")
	}
	for i, e := range ctx.v.Entries {
		fmt.Printf("%d) %s - %s\n", i+1, e.Service, e.Username)
	}
	idxStr := readLine("Entry number to delete: ")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 1 || idx > len(ctx.v.Entries) {
		return errors.New("invalid entry number")
	}

	ctx.v.Entries = append(ctx.v.Entries[:idx-1], ctx.v.Entries[idx:]...)
	newPlain, _ := json.Marshal(ctx.v)
	newEncVault, newVaultNonce, err := crypto.EncryptAESGCM(ctx.masterKey, newPlain)
	if err != nil {
		return fmt.Errorf("encrypt updated vault: %w", err)
	}
	apiClient := api.NewClientAPI(baseURL)
	if err := apiClient.PostStore(userID, ctx.serverShare, newEncVault, newVaultNonce, ""); err != nil {
		return fmt.Errorf("post store: %w", err)
	}
	if err := ctx.cs.SaveLocal(userID, ctx.encLocal, ctx.salt, ctx.localNonce, newEncVault, newVaultNonce); err != nil {
		return fmt.Errorf("save local backup: %w", err)
	}
	fmt.Println("Entry deleted and vault saved")
	return nil
}

func openBackup(dbDir, userID string) error {
	pw, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	rec := readLine("Recovery share (base64): ")
	cs := storage.NewClientStore(dbDir)
	v, err := vault.OpenBackupVault(cs, vault.BackupInput{
		UserID:          userID,
		MasterPassword:  pw,
		RecoveryShare64: rec,
	})
	if err != nil {
		return fmt.Errorf("backup open failed: %w", err)
	}
	fmt.Println("Backup mode (read-only)")
	if len(v.Entries) == 0 {
		fmt.Println("Vault entries: (empty)")
		return nil
	}
	for i, e := range v.Entries {
		fmt.Printf("%d) %s - %s - %s\n", i+1, e.Service, e.Username, e.Password)
		if e.Notes != "" {
			fmt.Printf("    notes: %s\n", e.Notes)
		}
	}
	return nil
}

func runVisual(userID, outDir string) error {
	rec := readLine("Recovery share (base64): ")
	if outDir == "" {
		outDir = filepath.Join("data", "visual", userID)
	}
	paths, err := visual.GenerateVisualShares(rec, outDir)
	if err != nil {
		return err
	}
	fmt.Println("QR and visual shares saved:")
	fmt.Printf("  QR: %s\n", paths.QRPath)
	fmt.Printf("  Share1: %s\n", paths.Share1Path)
	fmt.Printf("  Share2: %s\n", paths.Share2Path)
	fmt.Printf("  Combined: %s\n", paths.CombinedPath)
	return nil
}

func main() {
	baseURL := flag.String("server", "http://localhost:8080", "server base url")
	dbDir := flag.String("local", "data/client", "local client storage dir")
	visualOut := flag.String("visual-out", "", "output dir for visual shares")
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Println("usage: client <create|open|add|edit|delete|backup|visual> <user>")
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
	case "edit":
		if err := editEntry(*baseURL, *dbDir, user); err != nil {
			log.Fatal(err)
		}
	case "delete":
		if err := deleteEntry(*baseURL, *dbDir, user); err != nil {
			log.Fatal(err)
		}
	case "backup":
		if err := openBackup(*dbDir, user); err != nil {
			log.Fatal(err)
		}
	case "visual":
		if err := runVisual(user, *visualOut); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Println("unknown command")
	}
}
