package vaultsdk

import "fmt"

// Error represents an error returned by the Vault API.
type Error struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Errors contains the error messages from the Vault response.
	Errors []string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("vault: HTTP %d", e.StatusCode)
	}
	if len(e.Errors) == 1 {
		return fmt.Sprintf("vault: %s (HTTP %d)", e.Errors[0], e.StatusCode)
	}
	return fmt.Sprintf("vault: %v (HTTP %d)", e.Errors, e.StatusCode)
}
