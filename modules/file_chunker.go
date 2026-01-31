package modules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileChunkSize defines the maximum size for password file chunks (in bytes)
// Default: 500 MB per chunk
const FileChunkSize = 500 * 1024 * 1024

// LargeFileThreshold defines the file size threshold for automatic chunking (in bytes)
// Default: 1 GB
const LargeFileThreshold = 1 * 1024 * 1024 * 1024

// DisableFileChunking is a global flag to disable automatic file chunking
var DisableFileChunking = false

// ChunkedFile represents a large file that has been split into chunks
type ChunkedFile struct {
	OriginalPath string
	ChunkPaths   []string
	TempDir      string
	ChunkSize    int64
	IsChunked    bool
	mutex        sync.Mutex
}

// NewChunkedFile creates a chunked file manager
func NewChunkedFile(filePath string) (*ChunkedFile, error) {
	cf := &ChunkedFile{
		OriginalPath: filePath,
		ChunkSize:    FileChunkSize,
		IsChunked:    false,
	}

	// Check if chunking is disabled
	if DisableFileChunking {
		cf.ChunkPaths = []string{filePath}
		return cf, nil
	}

	// Get file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// If file is small enough, don't chunk it
	if fileInfo.Size() < LargeFileThreshold {
		cf.ChunkPaths = []string{filePath}
		return cf, nil
	}

	// File is large, need to chunk it
	fmt.Fprintf(os.Stderr, "[INFO] Large file detected (%d MB), creating chunks...\n", fileInfo.Size()/(1024*1024))
	if err := cf.createChunks(); err != nil {
		return nil, fmt.Errorf("failed to create chunks: %w", err)
	}

	return cf, nil
}

// createChunks splits the large file into smaller chunks
func (cf *ChunkedFile) createChunks() error {
	cf.mutex.Lock()
	defer cf.mutex.Unlock()

	// Create temporary directory for chunks
	tempDir, err := os.MkdirTemp("", "brutespray-chunks-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	cf.TempDir = tempDir
	cf.IsChunked = true

	// Open the original file
	file, err := os.Open(cf.OriginalPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length

	chunkIndex := 0
	var currentChunk *os.File
	var currentSize int64
	var chunkPaths []string

	for scanner.Scan() {
		line := scanner.Text()
		lineSize := int64(len(line) + 1) // +1 for newline

		// Check if we need to start a new chunk
		if currentChunk == nil || currentSize+lineSize > cf.ChunkSize {
			// Close previous chunk if exists
			if currentChunk != nil {
				currentChunk.Close()
			}

			// Create new chunk file
			chunkPath := filepath.Join(cf.TempDir, fmt.Sprintf("chunk_%04d.txt", chunkIndex))
			currentChunk, err = os.Create(chunkPath)
			if err != nil {
				return fmt.Errorf("failed to create chunk file: %w", err)
			}
			chunkPaths = append(chunkPaths, chunkPath)
			chunkIndex++
			currentSize = 0

			fmt.Fprintf(os.Stderr, "[INFO] Created chunk %d: %s\n", chunkIndex, chunkPath)
		}

		// Write line to current chunk
		if _, err := fmt.Fprintln(currentChunk, line); err != nil {
			currentChunk.Close()
			return fmt.Errorf("failed to write to chunk: %w", err)
		}
		currentSize += lineSize
	}

	// Close last chunk
	if currentChunk != nil {
		currentChunk.Close()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	cf.ChunkPaths = chunkPaths
	fmt.Fprintf(os.Stderr, "[INFO] Successfully created %d chunks\n", len(chunkPaths))

	return nil
}

// Cleanup removes temporary chunk files
func (cf *ChunkedFile) Cleanup() error {
	cf.mutex.Lock()
	defer cf.mutex.Unlock()

	if !cf.IsChunked || cf.TempDir == "" {
		return nil
	}

	fmt.Fprintf(os.Stderr, "[INFO] Cleaning up temporary chunk files in %s\n", cf.TempDir)
	err := os.RemoveAll(cf.TempDir)
	if err != nil {
		return fmt.Errorf("failed to remove temp directory: %w", err)
	}

	cf.TempDir = ""
	cf.ChunkPaths = nil
	return nil
}

// GetChunkPaths returns the list of chunk file paths
func (cf *ChunkedFile) GetChunkPaths() []string {
	cf.mutex.Lock()
	defer cf.mutex.Unlock()
	return cf.ChunkPaths
}

// ChunkIterator provides sequential access to file chunks
type ChunkIterator struct {
	chunks       []string
	currentIndex int
	currentFile  *os.File
	scanner      *bufio.Scanner
	cleanup      func() error
}

// NewChunkIterator creates a new chunk iterator
func NewChunkIterator(cf *ChunkedFile) *ChunkIterator {
	return &ChunkIterator{
		chunks:       cf.GetChunkPaths(),
		currentIndex: -1,
		cleanup:      cf.Cleanup,
	}
}

// NextChunk advances to the next chunk and returns a scanner for it
func (ci *ChunkIterator) NextChunk() (*bufio.Scanner, bool) {
	// Close current file if open
	if ci.currentFile != nil {
		ci.currentFile.Close()
		ci.currentFile = nil
	}

	ci.currentIndex++
	if ci.currentIndex >= len(ci.chunks) {
		return nil, false
	}

	// Open next chunk
	file, err := os.Open(ci.chunks[ci.currentIndex])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to open chunk %d: %v\n", ci.currentIndex, err)
		return nil, false
	}

	ci.currentFile = file
	ci.scanner = bufio.NewScanner(file)
	ci.scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length

	return ci.scanner, true
}

// Close closes the current file and performs cleanup
func (ci *ChunkIterator) Close() error {
	if ci.currentFile != nil {
		ci.currentFile.Close()
		ci.currentFile = nil
	}

	if ci.cleanup != nil {
		return ci.cleanup()
	}

	return nil
}

// CountLinesInChunkedFile counts total lines across all chunks
func CountLinesInChunkedFile(cf *ChunkedFile) (int, error) {
	count := 0

	for _, chunkPath := range cf.GetChunkPaths() {
		file, err := os.Open(chunkPath)
		if err != nil {
			return 0, fmt.Errorf("failed to open chunk for counting: %w", err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			count++
		}

		file.Close()

		if err := scanner.Err(); err != nil {
			return 0, fmt.Errorf("error reading chunk for counting: %w", err)
		}
	}

	return count, nil
}

// ReadLinesFromChunkedFile reads all lines from chunked file (memory efficient)
func ReadLinesFromChunkedFile(cf *ChunkedFile, callback func(string) error) error {
	for _, chunkPath := range cf.GetChunkPaths() {
		file, err := os.Open(chunkPath)
		if err != nil {
			return fmt.Errorf("failed to open chunk: %w", err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		
		for scanner.Scan() {
			if err := callback(scanner.Text()); err != nil {
				file.Close()
				return err
			}
		}

		file.Close()

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading chunk: %w", err)
		}
	}

	return nil
}

// CopyReaderToFile copies data from reader to file efficiently
func CopyReaderToFile(reader io.Reader, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	_, err = io.Copy(writer, reader)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}
