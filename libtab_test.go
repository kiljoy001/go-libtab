package libtab

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNDBParser(t *testing.T) {
	input := `# This is a comment
schema=users
	col=user
	col=uid

user=alice
	uid=1000
`
	tuples, err := parseNDB(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseNDB failed: %v", err)
	}
	if len(tuples) != 2 {
		t.Fatalf("expected 2 tuples, got %d", len(tuples))
	}

	schema, err := parseSchema(tuples[0])
	if err != nil {
		t.Fatalf("parseSchema failed: %v", err)
	}

	row, err := schema.ValidateRow(flattenTuple(tuples[1]))
	if err != nil {
		t.Fatalf("ValidateRow failed: %v", err)
	}

	if row.Values["user"] != "alice" || row.Values["uid"] != "1000" {
		t.Errorf("wrong row values: %+v", row.Values)
	}
}

func TestTableCreateAndCommit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "libtab-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "users.tab")
	cols := []Column{
		{Name: "user"},
		{Name: "uid"},
		{Name: "shell"},
	}

	t1 := Create(dbPath, "users", cols)
	_, err = t1.AddRow(map[string]string{
		"user":  "alice",
		"uid":   "1000",
		"shell": "/bin/rc",
	})
	if err != nil {
		t.Fatalf("AddRow failed: %v", err)
	}

	_, err = t1.AddRow(map[string]string{
		"user":  "bob",
		"uid":   "1001",
		"shell": "/bin/bash",
	})
	if err != nil {
		t.Fatalf("AddRow failed: %v", err)
	}

	if err := t1.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify file exists and has content
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("committed file does not exist")
	}

	// Load it back
	t2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if t2.Schema.Name != "users" {
		t.Errorf("schema name mismatch: %s", t2.Schema.Name)
	}

	if len(t2.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(t2.Rows))
	}

	alice := t2.Search("user", "alice")
	if len(alice) != 1 {
		t.Fatalf("alice row not found")
	}
	if alice[0].Values["uid"] != "1000" || alice[0].Values["shell"] != "/bin/rc" {
		t.Errorf("wrong values for alice: %+v", alice[0].Values)
	}
}

func TestHashedColumns(t *testing.T) {
	preimage := []byte("mysecretpassword")

	// Test Blake2b
	blakeCell, err := HashBlake2b(preimage)
	if err != nil {
		t.Fatalf("HashBlake2b failed: %v", err)
	}
	if !strings.HasPrefix(blakeCell, "hashed:") {
		t.Errorf("wrong blake cell format: %s", blakeCell)
	}

	ok, err := VerifyHash(blakeCell, preimage)
	if err != nil {
		t.Fatalf("VerifyHash failed: %v", err)
	}
	if !ok {
		t.Errorf("blake verification failed")
	}

	ok, err = VerifyHash(blakeCell, []byte("wrongpassword"))
	if err != nil {
		t.Fatalf("VerifyHash failed: %v", err)
	}
	if ok {
		t.Errorf("blake verification succeeded on wrong preimage")
	}

	// Test Argon2id
	argonCell, err := HashArgon2id(preimage)
	if err != nil {
		t.Fatalf("HashArgon2id failed: %v", err)
	}
	if !strings.HasPrefix(argonCell, "hashed:") {
		t.Errorf("wrong argon cell format: %s", argonCell)
	}

	ok, err = VerifyHash(argonCell, preimage)
	if err != nil {
		t.Fatalf("VerifyHash failed: %v", err)
	}
	if !ok {
		t.Errorf("argon verification failed")
	}

	ok, err = VerifyHash(argonCell, []byte("wrongpassword"))
	if err != nil {
		t.Fatalf("VerifyHash failed: %v", err)
	}
	if ok {
		t.Errorf("argon verification succeeded on wrong preimage")
	}
}

func TestSignedColumns(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	body := []byte("important audit log content")

	signedCell, err := SignBody(body, privKey)
	if err != nil {
		t.Fatalf("SignBody failed: %v", err)
	}
	if !strings.HasPrefix(signedCell, "signed:") {
		t.Errorf("wrong signed cell format: %s", signedCell)
	}

	verifiedBody, err := VerifySignature(signedCell, pubKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if string(verifiedBody) != string(body) {
		t.Errorf("verified body mismatch: %s vs %s", string(verifiedBody), string(body))
	}

	// Verify failure on tampered content
	tamperedCell := strings.Replace(signedCell, "a", "b", 1)
	_, err = VerifySignature(tamperedCell, pubKey)
	if err == nil {
		t.Errorf("VerifySignature succeeded on tampered cell")
	}

	// Verify failure with wrong public key
	otherPubKey, _, _ := ed25519.GenerateKey(nil)
	_, err = VerifySignature(signedCell, otherPubKey)
	if err == nil {
		t.Errorf("VerifySignature succeeded with wrong public key")
	}
}

func TestEncryptedColumns(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	body := []byte("highly sensitive cookie session identifier")

	encCell, err := EncryptBody(body, key)
	if err != nil {
		t.Fatalf("EncryptBody failed: %v", err)
	}
	if !strings.HasPrefix(encCell, "encrypted:") {
		t.Errorf("wrong encrypted cell format: %s", encCell)
	}

	decrypted, err := DecryptBody(encCell, key)
	if err != nil {
		t.Fatalf("DecryptBody failed: %v", err)
	}
	if string(decrypted) != string(body) {
		t.Errorf("decrypted body mismatch: %s vs %s", string(decrypted), string(body))
	}

	// Verify decryption failure with wrong key
	wrongKey := make([]byte, 32)
	wrongKey[0] = 99
	_, err = DecryptBody(encCell, wrongKey)
	if err == nil {
		t.Errorf("DecryptBody succeeded with wrong key")
	}
}

// Helpers
func stringsContains(s, sub string) bool {
	return strings.Contains(s, sub)
}

