// Package storage provides storage operations for the crypto secrets engine.
package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/ABT-Tech-Limited/vault-plugin-secrets-crypto/internal/model"
)

const (
	// keyPrefix is the storage prefix for key data.
	keyPrefix = "keys/"
	// indexNamePrefix is the storage prefix for name index.
	indexNamePrefix = "index/name/"
	// indexExtIDPrefix is the storage prefix for external_id index.
	indexExtIDPrefix = "index/external_id/"
)

// KeyStorage provides storage operations for keys.
type KeyStorage struct {
	storage logical.Storage
}

// NewKeyStorage creates a new KeyStorage instance.
func NewKeyStorage(s logical.Storage) *KeyStorage {
	return &KeyStorage{storage: s}
}

// SaveKey saves a key and creates necessary indexes.
// Returns an error if name or external_id already exists for a different key.
func (ks *KeyStorage) SaveKey(ctx context.Context, key *model.Key) error {
	// Check name uniqueness
	if key.Name != "" {
		existing, err := ks.GetByName(ctx, key.Name)
		if err != nil {
			return fmt.Errorf("failed to check name uniqueness: %w", err)
		}
		if existing != nil && existing.InternalID != key.InternalID {
			return fmt.Errorf("name '%s' already exists", key.Name)
		}
	}

	// Check external_id uniqueness
	if key.ExternalID != "" {
		existing, err := ks.GetByExternalID(ctx, key.ExternalID)
		if err != nil {
			return fmt.Errorf("failed to check external_id uniqueness: %w", err)
		}
		if existing != nil && existing.InternalID != key.InternalID {
			return fmt.Errorf("external_id '%s' already exists", key.ExternalID)
		}
	}

	// Serialize key
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Store key with SealWrap enabled
	entry := &logical.StorageEntry{
		Key:      keyPrefix + key.InternalID,
		Value:    data,
		SealWrap: true,
	}
	if err := ks.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	// Create name index
	if key.Name != "" {
		indexEntry := &logical.StorageEntry{
			Key:   indexNamePrefix + key.Name,
			Value: []byte(key.InternalID),
		}
		if err := ks.storage.Put(ctx, indexEntry); err != nil {
			return fmt.Errorf("failed to create name index: %w", err)
		}
	}

	// Create external_id index
	if key.ExternalID != "" {
		indexEntry := &logical.StorageEntry{
			Key:   indexExtIDPrefix + key.ExternalID,
			Value: []byte(key.InternalID),
		}
		if err := ks.storage.Put(ctx, indexEntry); err != nil {
			return fmt.Errorf("failed to create external_id index: %w", err)
		}
	}

	return nil
}

// GetByInternalID retrieves a key by its internal ID.
// Returns nil if the key is not found.
func (ks *KeyStorage) GetByInternalID(ctx context.Context, id string) (*model.Key, error) {
	entry, err := ks.storage.Get(ctx, keyPrefix+id)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var key model.Key
	if err := json.Unmarshal(entry.Value, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}
	return &key, nil
}

// GetByName retrieves a key by its name.
// Returns nil if not found.
func (ks *KeyStorage) GetByName(ctx context.Context, name string) (*model.Key, error) {
	entry, err := ks.storage.Get(ctx, indexNamePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("failed to read name index: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	return ks.GetByInternalID(ctx, string(entry.Value))
}

// GetByExternalID retrieves a key by its external ID.
// Returns nil if not found.
func (ks *KeyStorage) GetByExternalID(ctx context.Context, extID string) (*model.Key, error) {
	entry, err := ks.storage.Get(ctx, indexExtIDPrefix+extID)
	if err != nil {
		return nil, fmt.Errorf("failed to read external_id index: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	return ks.GetByInternalID(ctx, string(entry.Value))
}

// ListKeys returns a list of all key internal IDs.
func (ks *KeyStorage) ListKeys(ctx context.Context) ([]string, error) {
	entries, err := ks.storage.List(ctx, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	return entries, nil
}

// ListExternalIDs returns a list of all key external IDs.
func (ks *KeyStorage) ListExternalIDs(ctx context.Context) ([]string, error) {
	entries, err := ks.storage.List(ctx, indexExtIDPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list external IDs: %w", err)
	}
	return entries, nil
}
