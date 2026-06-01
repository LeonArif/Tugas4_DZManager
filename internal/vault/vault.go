package vault

// vault data structures.

type Entry struct {
	Service string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Notes string `json:"notes,omitempty"`
}

type Vault struct {
	Entries []Entry `json:"entries"`
}
