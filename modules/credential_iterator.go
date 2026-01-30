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

	// Store original file paths for reopening if needed
	passwordFilePath string

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

	fmt.Fprintf(os.Stderr, "[DEBUG] Initializing credential iterator for %s:%d\n", ci.host.Host, ci.host.Port)

	ci.initialized = true

	if ci.isComboMode {
		return ci.initializeCombo()
	}

	// For password-only services, skip user initialization
	if ci.isPasswordOnly {
		ci.users = []string{""}
		ci.userIndex = 0
		ci.currentUser = ""
	} else {
		// Initialize users
		if ci.user != "" {
			if IsFile(ci.user) {
				fmt.Fprintf(os.Stderr, "[DEBUG] Opening user file: %s\n", ci.user)
				file, err := os.Open(ci.user)
				if err != nil {
					return fmt.Errorf("error opening user file: %w", err)
				}
				ci.userFile = file
				ci.userScanner = bufio.NewScanner(file)
				ci.userScanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length
				fmt.Fprintf(os.Stderr, "[DEBUG] User file opened successfully\n")
			} else {
				ci.users = []string{ci.user}
			}
		} else {
			// Use default wordlist
			ci.useDefaultUsers = true
			ci.users = GetUsersFromDefaultWordlist(ci.version, ci.host.Service)
		}
	}

	// Initialize passwords
	if ci.password != "" {
		if IsFile(ci.password) {
			fmt.Fprintf(os.Stderr, "[DEBUG] Opening password file: %s\n", ci.password)
			file, err := os.Open(ci.password)
			if err != nil {
				ci.Close() // Clean up user file if opened
				return fmt.Errorf("error opening password file: %w", err)
			}
			ci.passwordFile = file
			ci.passwordFilePath = ci.password // Store path for potential reopening
			ci.passScanner = bufio.NewScanner(file)
			ci.passScanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length
			fmt.Fprintf(os.Stderr, "[DEBUG] Password file opened successfully\n")
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

	return nil
}

// initializeCombo sets up combo mode iteration
func (ci *CredentialIterator) initializeCombo() error {
	if IsFile(ci.combo) {
		fmt.Fprintf(os.Stderr, "[DEBUG] Opening combo file: %s\n", ci.combo)
		file, err := os.Open(ci.combo)
		if err != nil {
			return fmt.Errorf("error opening combo file: %w", err)
		}
		ci.comboFile = file
		ci.comboScanner = bufio.NewScanner(file)
		ci.comboScanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length
		fmt.Fprintf(os.Stderr, "[DEBUG] Combo file opened successfully\n")
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
			ci.done = true // Prevent retry attempts after initialization failure
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
			splits := strings.SplitN(line, ":", 2)
			if len(splits) == 2 {
				return splits[0], splits[1], true
			} else {
				// Skip invalid lines with a warning instead of terminating
				fmt.Fprintf(os.Stderr, "[WARNING] Skipping invalid format in combo file: %s\n", line)
				continue
			}
		}
		if err := ci.comboScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Error reading combo file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[DEBUG] Reached end of combo file\n")
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
			fmt.Fprintf(os.Stderr, "[ERROR] Error reading password file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[DEBUG] Reached end of password file\n")
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
			fmt.Fprintf(os.Stderr, "[DEBUG] No more users available\n")
			ci.done = true
			return "", "", false
		}
		fmt.Fprintf(os.Stderr, "[DEBUG] Processing user: %s\n", ci.currentUser)
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
			fmt.Fprintf(os.Stderr, "[ERROR] Error reading user file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[DEBUG] Reached end of user file\n")
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
			fmt.Fprintf(os.Stderr, "[ERROR] Error reading password file: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[DEBUG] Reached end of password file\n")
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
				// If seek fails and we have the file path, try to reopen
				if ci.passwordFilePath != "" {
					ci.passwordFile.Close()
					file, err := os.Open(ci.passwordFilePath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error reopening password file: %v\n", err)
						ci.done = true
						return
					}
					ci.passwordFile = file
				} else {
					// No file path stored, can't reopen
					fmt.Fprintf(os.Stderr, "Error seeking password file and no path to reopen: %v\n", err)
					ci.done = true
					return
				}
			}
			ci.passScanner = bufio.NewScanner(ci.passwordFile)
			ci.passScanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length
		}
	} else {
		// Just reset index for slice-based passwords
		ci.passIndex = 0
	}
	ci.currentPassword = ""
}

// Close cleans up file handles
func (ci *CredentialIterator) Close() error {
	var errors []error

	if ci.userFile != nil {
		if err := ci.userFile.Close(); err != nil {
			errors = append(errors, fmt.Errorf("error closing user file: %w", err))
		}
		ci.userFile = nil
	}

	if ci.passwordFile != nil {
		if err := ci.passwordFile.Close(); err != nil {
			errors = append(errors, fmt.Errorf("error closing password file: %w", err))
		}
		ci.passwordFile = nil
	}

	if ci.comboFile != nil {
		if err := ci.comboFile.Close(); err != nil {
			errors = append(errors, fmt.Errorf("error closing combo file: %w", err))
		}
		ci.comboFile = nil
	}

	if len(errors) > 0 {
		// Return the first error, but log all errors to stderr
		for i, err := range errors {
			if i == 0 {
				continue // Will return this one
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		return errors[0]
	}

	return nil
}
