package backend

import (
	"fmt"
	"regexp"
)

const (
	// MaxNameLength is the maximum length for key names.
	MaxNameLength = 128
	// MaxExternalIDLength is the maximum length for external IDs.
	MaxExternalIDLength = 256
	// MaxMetadataKeys is the maximum number of metadata keys.
	MaxMetadataKeys = 16
	// MaxMetadataKeyLen is the maximum length for a metadata key.
	MaxMetadataKeyLen = 64
	// MaxMetadataValueLen is the maximum length for a metadata value.
	MaxMetadataValueLen = 256
	// MaxDataLength is the maximum length for data to sign (1MB).
	MaxDataLength = 1024 * 1024
)

// namePattern allows alphanumeric, underscore, and hyphen.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidateName validates a key name.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > MaxNameLength {
		return fmt.Errorf("name exceeds maximum length of %d characters", MaxNameLength)
	}
	if !namePattern.MatchString(name) {
		return fmt.Errorf("name contains invalid characters: only alphanumeric, underscore, and hyphen allowed")
	}
	return nil
}

// externalIDPattern allows alphanumeric, dot, underscore, and hyphen.
var externalIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ValidateExternalID validates an external ID.
func ValidateExternalID(extID string) error {
	if extID == "" {
		return fmt.Errorf("external_id is required")
	}
	if len(extID) > MaxExternalIDLength {
		return fmt.Errorf("external_id exceeds maximum length of %d characters", MaxExternalIDLength)
	}
	if !externalIDPattern.MatchString(extID) {
		return fmt.Errorf("external_id contains invalid characters: only alphanumeric, dot, underscore, and hyphen allowed")
	}
	return nil
}

// ValidateMetadata validates metadata key-value pairs.
func ValidateMetadata(metadata map[string]string) error {
	if metadata == nil {
		return nil
	}
	if len(metadata) > MaxMetadataKeys {
		return fmt.Errorf("metadata exceeds maximum of %d keys", MaxMetadataKeys)
	}
	for k, v := range metadata {
		if len(k) > MaxMetadataKeyLen {
			return fmt.Errorf("metadata key '%s' exceeds maximum length of %d characters", k, MaxMetadataKeyLen)
		}
		if len(v) > MaxMetadataValueLen {
			return fmt.Errorf("metadata value for key '%s' exceeds maximum length of %d characters", k, MaxMetadataValueLen)
		}
	}
	return nil
}

// ValidateSignData validates data to be signed.
func ValidateSignData(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}
	if len(data) > MaxDataLength {
		return fmt.Errorf("data exceeds maximum length of %d bytes", MaxDataLength)
	}
	return nil
}
