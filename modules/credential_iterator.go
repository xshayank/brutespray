package modules

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CredentialIterator provides lazy/streaming credential generation
// to avoid loading entire wordlists into memory
type CredentialIterator struct {
	// Configuration
	host     *Host
	user     string
	password string
	combo    string
	version  string

	// State for iteration
	userFile     *os.File
	passwordFile *os.File
	userScanner  *bufio.Scanner
	passScanner  *bufio.Scanner
	comboFile    *os.File
	comboScanner *bufio.Scanner

	// Current values
	currentUser     string
	currentPassword string
	users           []string
	passwords       []string
	userIndex       int
	passIndex       int

	// Flags
	isComboMode     bool
	isPasswordOnly  bool // For VNC, SNMP
	useDefaultUsers bool
	useDefaultPass  bool
	done            bool
	initialized     bool
}

// NewCredentialIterator creates a new credential iterator
func NewCredentialIterator(host *Host, user, password, combo, version string, isPasswordOnly bool) (*CredentialIterator, error) {
	iter := &CredentialIterator{
		host:           host,
		user:           user,
		password:       password,
		combo:          combo,
		version:        version,
		isPasswordOnly: isPasswordOnly,
		isComboMode:    combo != "",
	}

	return iter, nil
}

// initialize sets up the iterator on first use
func (ci *CredentialIterator) initialize() error {
	if ci.initialized {
		return nil
	}
	ci.initialized = true

	if ci.isComboMode {
		return ci.initializeCombo()
	}

	// Initialize users
	if ci.user != "" {
		if IsFile(ci.user) {
			file, err := os.Open(ci.user)
			if err != nil {
				return fmt.Errorf("error opening user file: %w", err)
			}
			ci.userFile = file
			ci.userScanner = bufio.NewScanner(file)
		} else {
			ci.users = []string{ci.user}
		}
	} else {
		// Use default wordlist
		ci.useDefaultUsers = true
		ci.users = GetUsersFromDefaultWordlist(ci.version, ci.host.Service)
	}

	// Initialize passwords
	if ci.password != "" {
		if IsFile(ci.password) {
			file, err := os.Open(ci.password)
			if err != nil {
				ci.Close() // Clean up user file if opened
				return fmt.Errorf("error opening password file: %w", err)
			}
			ci.passwordFile = file
			ci.passScanner = bufio.NewScanner(file)
		} else {
			ci.passwords = []string{ci.password}
		}
	} else {
		if UseEmptyPassword {
			// Use a single empty password
			ci.passwords = []string{""}
		} else {
			// Use default wordlist
			ci.useDefaultPass = true
			ci.passwords = GetPasswordsFromDefaultWordlist(ci.version, ci.host.Service)
		}
	}

	// For password-only services, we don't need users
	if ci.isPasswordOnly {
		ci.users = []string{""}
		ci.userIndex = 0
		ci.currentUser = ""
	}

	return nil
}

// initializeCombo sets up combo mode iteration
func (ci *CredentialIterator) initializeCombo() error {
	if IsFile(ci.combo) {
		file, err := os.Open(ci.combo)
		if err != nil {
			return fmt.Errorf("error opening combo file: %w", err)
		}
		ci.comboFile = file
		ci.comboScanner = bufio.NewScanner(file)
	} else {
		// Single combo value
		splits := strings.SplitN(ci.combo, ":", 2)
		if len(splits) != 2 {
			return fmt.Errorf("invalid combo format, expected user:password")
		}
		ci.users = []string{splits[0]}
		ci.passwords = []string{splits[1]}
	}
	return nil
}

// Next returns the next credential, or false if done
func (ci *CredentialIterator) Next() (user, password string, ok bool) {
	if !ci.initialized {
		if err := ci.initialize(); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing credential iterator: %v\n", err)
			return "", "", false
		}
	}

	if ci.done {
		return "", "", false
	}

	if ci.isComboMode {
		return ci.nextCombo()
	}

	// For password-only services (VNC, SNMP), iterate only passwords
	if ci.isPasswordOnly {
		return ci.nextPasswordOnly()
	}

	// Standard mode: iterate all user/password combinations
	return ci.nextStandard()
}

// nextCombo returns next credential in combo mode
func (ci *CredentialIterator) nextCombo() (user, password string, ok bool) {
	if ci.comboScanner != nil {
		// Reading from file
		for ci.comboScanner.Scan() {
			line := ci.comboScanner.Text()
			if strings.Contains(line, ":") {
				splits := strings.SplitN(line, ":", 2)
				return splits[0], splits[1], true
			} else {
				// Skip invalid lines with a warning instead of terminating
				fmt.Fprintf(os.Stderr, "Warning: skipping invalid format in combo file: %s\n", line)
				continue
			}
		}
		if err := ci.comboScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading combo file: %v\n", err)
		}
		ci.done = true
		return "", "", false
	}

	// Single combo value
	if ci.userIndex < len(ci.users) {
		user := ci.users[ci.userIndex]
		pass := ci.passwords[ci.userIndex]
		ci.userIndex++
		return user, pass, true
	}

	ci.done = true
	return "", "", false
}

// nextPasswordOnly returns next password for password-only services
func (ci *CredentialIterator) nextPasswordOnly() (user, password string, ok bool) {
	if ci.passScanner != nil {
		// Reading from file
		if ci.passScanner.Scan() {
			return "", ci.passScanner.Text(), true
		}
		if err := ci.passScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", err)
		}
		ci.done = true
		return "", "", false
	}

	// Reading from slice
	if ci.passIndex < len(ci.passwords) {
		pass := ci.passwords[ci.passIndex]
		ci.passIndex++
		return "", pass, true
	}

	ci.done = true
	return "", "", false
}

// nextStandard returns next user/password combination in standard mode
func (ci *CredentialIterator) nextStandard() (user, password string, ok bool) {
	// If we need to advance to next user
	if ci.currentUser == "" {
		if !ci.nextUser() {
			ci.done = true
			return "", "", false
		}
	}

	// Try to get next password for current user
	if ci.nextPassword() {
		return ci.currentUser, ci.currentPassword, true
	}

	// No more passwords for current user, move to next user
	ci.resetPasswords()
	if !ci.nextUser() {
		ci.done = true
		return "", "", false
	}

	// Get first password for new user
	if ci.nextPassword() {
		return ci.currentUser, ci.currentPassword, true
	}

	// No passwords at all
	ci.done = true
	return "", "", false
}

// nextUser advances to the next user
func (ci *CredentialIterator) nextUser() bool {
	if ci.userScanner != nil {
		// Reading from file
		if ci.userScanner.Scan() {
			ci.currentUser = ci.userScanner.Text()
			return true
		}
		if err := ci.userScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading user file: %v\n", err)
		}
		return false
	}

	// Reading from slice
	if ci.userIndex < len(ci.users) {
		ci.currentUser = ci.users[ci.userIndex]
		ci.userIndex++
		return true
	}

	return false
}

// nextPassword advances to the next password
func (ci *CredentialIterator) nextPassword() bool {
	if ci.passScanner != nil {
		// Reading from file
		if ci.passScanner.Scan() {
			ci.currentPassword = ci.passScanner.Text()
			return true
		}
		if err := ci.passScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", err)
		}
		return false
	}

	// Reading from slice
	if ci.passIndex < len(ci.passwords) {
		ci.currentPassword = ci.passwords[ci.passIndex]
		ci.passIndex++
		return true
	}

	return false
}

// resetPasswords resets password iteration to start
func (ci *CredentialIterator) resetPasswords() {
	if ci.passScanner != nil {
		// For file-based passwords, seek back to beginning if possible
		if ci.passwordFile != nil {
			_, err := ci.passwordFile.Seek(0, 0)
			if err != nil {
				// If seek fails, try to reopen the file
				ci.passwordFile.Close()
				file, err := os.Open(ci.password)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reopening password file: %v\n", err)
					ci.done = true
					return
				}
				ci.passwordFile = file
			}
			ci.passScanner = bufio.NewScanner(ci.passwordFile)
		}
	} else {
		// Just reset index for slice-based passwords
		ci.passIndex = 0
	}
	ci.currentPassword = ""
}

// Close cleans up file handles
func (ci *CredentialIterator) Close() error {
	var lastErr error

	if ci.userFile != nil {
		if err := ci.userFile.Close(); err != nil {
			lastErr = err
		}
		ci.userFile = nil
	}

	if ci.passwordFile != nil {
		if err := ci.passwordFile.Close(); err != nil {
			lastErr = err
		}
		ci.passwordFile = nil
	}

	if ci.comboFile != nil {
		if err := ci.comboFile.Close(); err != nil {
			lastErr = err
		}
		ci.comboFile = nil
	}

	return lastErr
}
