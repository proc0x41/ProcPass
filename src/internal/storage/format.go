package storage

const FileVersion = "1.1"

const AADVEKWrap = "procpass:v1.1:vek-wrap"

type KDFParams struct {
	Algorithm   string `json:"algorithm"`
	Salt        []byte `json:"salt"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

type WrappedKey struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type EncryptedData struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type VaultFile struct {
	Version    string        `json:"version"`
	KDF        KDFParams     `json:"kdf"`
	WrappedVEK WrappedKey    `json:"wrapped_vek"`
	Vault      EncryptedData `json:"vault"`
}
