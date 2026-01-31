package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestFileChunking tests the file chunking functionality
func TestFileChunking(t *testing.T) {
	// Create a temporary test file
	tmpDir, err := os.MkdirTemp("", "brutespray-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test_passwords.txt")
	
	// Create a test file with known content
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Write 10,000 passwords
	expectedLines := 10000
	for i := 0; i < expectedLines; i++ {
		fmt.Fprintf(f, "password%d\n", i)
	}
	f.Close()

	// Test with chunking disabled
	DisableFileChunking = true
	cf1, err := NewChunkedFile(testFile)
	if err != nil {
		t.Fatalf("Failed to create chunked file with chunking disabled: %v", err)
	}
	
	if cf1.IsChunked {
		t.Error("Expected file not to be chunked when DisableFileChunking is true")
	}
	
	if len(cf1.ChunkPaths) != 1 || cf1.ChunkPaths[0] != testFile {
		t.Errorf("Expected single chunk path to be original file, got %v", cf1.ChunkPaths)
	}

	// Test with chunking enabled but file too small
	DisableFileChunking = false
	cf2, err := NewChunkedFile(testFile)
	if err != nil {
		t.Fatalf("Failed to create chunked file: %v", err)
	}
	defer cf2.Cleanup()

	if cf2.IsChunked {
		t.Error("Expected file not to be chunked when file is smaller than threshold")
	}

	// Count lines to verify
	count, err := CountLinesInChunkedFile(cf2)
	if err != nil {
		t.Fatalf("Failed to count lines: %v", err)
	}

	if count != expectedLines {
		t.Errorf("Expected %d lines, got %d", expectedLines, count)
	}

	t.Logf("Successfully tested file chunking with %d lines", count)
}

// TestChunkIterator tests the chunk iterator functionality
func TestChunkIterator(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "brutespray-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test_passwords.txt")
	
	// Create a test file
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	expectedLines := 1000
	for i := 0; i < expectedLines; i++ {
		fmt.Fprintf(f, "password%d\n", i)
	}
	f.Close()

	// Test reading with chunk iterator
	DisableFileChunking = false
	cf, err := NewChunkedFile(testFile)
	if err != nil {
		t.Fatalf("Failed to create chunked file: %v", err)
	}
	defer cf.Cleanup()

	// Read all lines using callback
	lineCount := 0
	err = ReadLinesFromChunkedFile(cf, func(line string) error {
		lineCount++
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to read lines: %v", err)
	}

	if lineCount != expectedLines {
		t.Errorf("Expected %d lines, got %d", lineCount, expectedLines)
	}

	t.Logf("Successfully read %d lines using chunk iterator", lineCount)
}
