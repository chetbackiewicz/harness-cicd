package main

import "os"

// readFile is split into its own function so tests can substitute the root.
// VULN: no containment check — caller may supply a fully traversed path.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
