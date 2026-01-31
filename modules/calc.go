package modules

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// UseEmptyPassword instructs GetUsersAndPasswords to include a single empty
// string (blank password) when the password flag was explicitly provided as
// empty by the user (e.g., -p ”).
var UseEmptyPassword bool

func GetUsersAndPasswordsCombo(h *Host, combo string, version string) ([]string, []string) {
	userSlice := []string{}
	passSlice := []string{}

	if IsFile(combo) {
		file, err := os.Open(combo)
		if err != nil {
			fmt.Println("Error opening combo file:", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, DefaultScannerBufferSize), MaxLineLength)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, ":") {
				splits := strings.SplitN(line, ":", 2)
				userSlice = append(userSlice, splits[0])
				passSlice = append(passSlice, splits[1])
			} else {
				fmt.Printf("Invalid format in combo file: %s\n", line)
				os.Exit(1)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading combo file:", err)
			os.Exit(1)
		}
	} else {
		splits := strings.SplitN(combo, ":", 2)
		userSlice = append(userSlice, splits[0])
		passSlice = append(passSlice, splits[1])
	}

	return userSlice, passSlice
}

func GetUsersAndPasswords(h *Host, user string, password string, version string) ([]string, []string) {
	userCh := make(chan string)
	passCh := make(chan string)

	go func() {
		defer close(userCh)
		if user != "" {
			if IsFile(user) {
				users, err := ReadUsersFromFile(user)
				if err != nil {
					fmt.Println("Error reading user file:", err)
					os.Exit(1)
				}
				for _, u := range users {
					userCh <- u
				}
			} else {
				userCh <- user
			}
		} else {
			var users []string = GetUsersFromDefaultWordlist(version, h.Service)
			for _, u := range users {
				userCh <- u
			}
		}
	}()

	go func() {
		defer close(passCh)
		if password != "" {
			if IsFile(password) {
				passwords, err := ReadPasswordsFromFile(password)
				if err != nil {
					fmt.Println("Error reading password file:", err)
					os.Exit(1)
				}
				for _, p := range passwords {
					passCh <- p
				}
			} else {
				passCh <- password
			}
		} else {
			if UseEmptyPassword {
				// Use a single empty password as explicitly requested
				passCh <- ""
			} else {
				var passwords []string = GetPasswordsFromDefaultWordlist(version, h.Service)
				for _, p := range passwords {
					passCh <- p
				}
			}
		}
	}()

	userSlice := []string{}
	for u := range userCh {
		userSlice = append(userSlice, u)
	}

	passwordSlice := []string{}
	for p := range passCh {
		passwordSlice = append(passwordSlice, p)
	}

	return userSlice, passwordSlice
}

func CalcCombinations(userCh []string, passCh []string) int {
	var totalCombinations int
	users := []string{}
	passwords := []string{}

	for u := range userCh {
		users = append(users, strconv.Itoa(u))
	}

	for p := range passCh {
		passwords = append(passwords, strconv.Itoa(p))
	}

	totalCombinations = len(users) * len(passwords)
	return totalCombinations
}

func CalcCombinationsPass(passCh []string) int {
	var totalCombinations int
	passwords := []string{}

	for p := range passCh {
		passwords = append(passwords, strconv.Itoa(p))
	}

	totalCombinations = len(passwords)
	return totalCombinations
}

func CalcCombinationsCombo(userCh []string, passCh []string) int {
	var totalCombinations int
	users := []string{}

	for u := range userCh {
		users = append(users, strconv.Itoa(u))
	}

	totalCombinations = len(users)
	return totalCombinations
}

// GetCredentialIterator creates an iterator for streaming credentials
func GetCredentialIterator(h *Host, user, password, combo, version string, isPasswordOnly bool) (*CredentialIterator, error) {
	return NewCredentialIterator(h, user, password, combo, version, isPasswordOnly)
}

// CountCredentials counts total credentials without loading them all into memory
func CountCredentials(h *Host, user, password, combo, version string, isPasswordOnly bool) int {
	fmt.Fprintf(os.Stderr, "[*] Counting credentials for %s:%d...\n", h.Host, h.Port)
	
	count := 0

	if combo != "" {
		// Count combo credentials
		if IsFile(combo) {
			fmt.Fprintf(os.Stderr, "[*] Counting combo file: %s\n", combo)
			file, err := os.Open(combo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening combo file for counting: %v\n", err)
				return 0
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			scanner.Buffer(make([]byte, DefaultScannerBufferSize), MaxLineLength)
			for scanner.Scan() {
				line := scanner.Text()
				splits := strings.SplitN(line, ":", 2)
				if len(splits) == 2 {
					count++ // Only count valid combo lines
					if count%100000 == 0 {
						fmt.Fprintf(os.Stderr, "[*] Counted %d combo lines so far...\n", count)
					}
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading combo file for counting: %v\n", err)
				return 0
			}
			fmt.Fprintf(os.Stderr, "[*] Total combo lines: %d\n", count)
		} else {
			count = 1 // Single combo value
		}
		return count
	}

	// Count users
	userCount := 0
	if isPasswordOnly {
		userCount = 1 // Password-only services use empty user
	} else if user != "" {
		if IsFile(user) {
			fmt.Fprintf(os.Stderr, "[*] Counting user file: %s\n", user)
			file, err := os.Open(user)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening user file for counting: %v\n", err)
				return 0
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			scanner.Buffer(make([]byte, DefaultScannerBufferSize), MaxLineLength)
			for scanner.Scan() {
				userCount++
				if userCount%10000 == 0 {
					fmt.Fprintf(os.Stderr, "[*] Counted %d users so far...\n", userCount)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading user file for counting: %v\n", err)
				return 0
			}
			fmt.Fprintf(os.Stderr, "[*] Total users: %d\n", userCount)
		} else {
			userCount = 1 // Single user value
		}
	} else {
		// Use default wordlist
		users := GetUsersFromDefaultWordlist(version, h.Service)
		userCount = len(users)
		fmt.Fprintf(os.Stderr, "[*] Using default user wordlist: %d users\n", userCount)
	}

	// Count passwords
	passCount := 0
	if password != "" {
		if IsFile(password) {
			fmt.Fprintf(os.Stderr, "[*] Counting password file: %s (this may take a while for large files)\n", password)
			file, err := os.Open(password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening password file for counting: %v\n", err)
				return 0
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			scanner.Buffer(make([]byte, DefaultScannerBufferSize), MaxLineLength)
			for scanner.Scan() {
				passCount++
				if passCount%100000 == 0 {
					fmt.Fprintf(os.Stderr, "[*] Counted %d passwords so far...\n", passCount)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading password file for counting: %v\n", err)
				return 0
			}
			fmt.Fprintf(os.Stderr, "[*] Total passwords: %d\n", passCount)
		} else {
			passCount = 1 // Single password value
		}
	} else {
		if UseEmptyPassword {
			passCount = 1 // Single empty password
		} else {
			// Use default wordlist
			passwords := GetPasswordsFromDefaultWordlist(version, h.Service)
			passCount = len(passwords)
			fmt.Fprintf(os.Stderr, "[*] Using default password wordlist: %d passwords\n", passCount)
		}
	}

	fmt.Fprintf(os.Stderr, "[*] Total combinations for %s:%d = %d users × %d passwords = %d\n",
		h.Host, h.Port, userCount, passCount, userCount*passCount)
	return userCount * passCount
}
