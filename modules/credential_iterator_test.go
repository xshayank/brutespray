package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestCredentialIteratorWithChunking tests the credential iterator with chunked files
func TestCredentialIteratorWithChunking(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "brutespray-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test password file
	passFile := filepath.Join(tmpDir, "passwords.txt")
	f, err := os.Create(passFile)
	if err != nil {
		t.Fatalf("Failed to create password file: %v", err)
	}

	expectedPasswords := 5000
	for i := 0; i < expectedPasswords; i++ {
		fmt.Fprintf(f, "pass%d\n", i)
	}
	f.Close()

	// Create test user file
	userFile := filepath.Join(tmpDir, "users.txt")
	f, err = os.Create(userFile)
	if err != nil {
		t.Fatalf("Failed to create user file: %v", err)
	}

	expectedUsers := 10
	for i := 0; i < expectedUsers; i++ {
		fmt.Fprintf(f, "user%d\n", i)
	}
	f.Close()

	// Create a mock host
	host := &Host{
		Host:    "127.0.0.1",
		Port:    22,
		Service: "ssh",
	}

	// Test with chunking disabled
	DisableFileChunking = true
	iter1, err := NewCredentialIterator(host, userFile, passFile, "", "1.0", false)
	if err != nil {
		t.Fatalf("Failed to create iterator: %v", err)
	}
	defer iter1.Close()

	count1 := 0
	for {
		u, p, ok := iter1.Next()
		if !ok {
			break
		}
		if u == "" || p == "" {
			t.Error("Got empty user or password")
		}
		count1++
	}

	expectedCombinations := expectedUsers * expectedPasswords
	if count1 != expectedCombinations {
		t.Errorf("Expected %d combinations, got %d (chunking disabled)", expectedCombinations, count1)
	}

	// Test with chunking enabled (but file is too small)
	DisableFileChunking = false
	iter2, err := NewCredentialIterator(host, userFile, passFile, "", "1.0", false)
	if err != nil {
		t.Fatalf("Failed to create iterator: %v", err)
	}
	defer iter2.Close()

	count2 := 0
	for {
		u, p, ok := iter2.Next()
		if !ok {
			break
		}
		if u == "" || p == "" {
			t.Error("Got empty user or password")
		}
		count2++
	}

	if count2 != expectedCombinations {
		t.Errorf("Expected %d combinations, got %d (chunking enabled)", expectedCombinations, count2)
	}

	t.Logf("Successfully iterated %d combinations with both chunking enabled and disabled", count2)
}

// TestCredentialIteratorPasswordOnly tests password-only mode with chunking
func TestCredentialIteratorPasswordOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "brutespray-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test password file
	passFile := filepath.Join(tmpDir, "passwords.txt")
	f, err := os.Create(passFile)
	if err != nil {
		t.Fatalf("Failed to create password file: %v", err)
	}

	expectedPasswords := 1000
	for i := 0; i < expectedPasswords; i++ {
		fmt.Fprintf(f, "pass%d\n", i)
	}
	f.Close()

	// Create a mock host for VNC (password-only service)
	host := &Host{
		Host:    "127.0.0.1",
		Port:    5900,
		Service: "vnc",
	}

	DisableFileChunking = false
	iter, err := NewCredentialIterator(host, "", passFile, "", "1.0", true)
	if err != nil {
		t.Fatalf("Failed to create iterator: %v", err)
	}
	defer iter.Close()

	count := 0
	for {
		u, p, ok := iter.Next()
		if !ok {
			break
		}
		if u != "" {
			t.Error("Expected empty user for password-only mode")
		}
		if p == "" {
			t.Error("Got empty password")
		}
		count++
	}

	if count != expectedPasswords {
		t.Errorf("Expected %d passwords, got %d", expectedPasswords, count)
	}

	t.Logf("Successfully iterated %d passwords in password-only mode", count)
}

// TestCredentialIteratorCombo tests combo mode with chunking
func TestCredentialIteratorCombo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "brutespray-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test combo file
	comboFile := filepath.Join(tmpDir, "combos.txt")
	f, err := os.Create(comboFile)
	if err != nil {
		t.Fatalf("Failed to create combo file: %v", err)
	}

	expectedCombos := 500
	for i := 0; i < expectedCombos; i++ {
		fmt.Fprintf(f, "user%d:pass%d\n", i, i)
	}
	f.Close()

	// Create a mock host
	host := &Host{
		Host:    "127.0.0.1",
		Port:    22,
		Service: "ssh",
	}

	DisableFileChunking = false
	iter, err := NewCredentialIterator(host, "", "", comboFile, "1.0", false)
	if err != nil {
		t.Fatalf("Failed to create iterator: %v", err)
	}
	defer iter.Close()

	count := 0
	for {
		u, p, ok := iter.Next()
		if !ok {
			break
		}
		if u == "" || p == "" {
			t.Error("Got empty user or password in combo mode")
		}
		count++
	}

	if count != expectedCombos {
		t.Errorf("Expected %d combos, got %d", expectedCombos, count)
	}

	t.Logf("Successfully iterated %d combos in combo mode", count)
}
