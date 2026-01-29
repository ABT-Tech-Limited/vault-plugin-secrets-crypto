package crypto

import (
	"runtime"
)

// ZeroBytes securely zeroes out a byte slice.
// This should be called after using sensitive data like private keys.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing
	runtime.KeepAlive(b)
}

// SecureBytes is a wrapper around a byte slice that provides secure cleanup.
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new SecureBytes with the specified size.
func NewSecureBytes(size int) *SecureBytes {
	return &SecureBytes{
		data: make([]byte, size),
	}
}

// Bytes returns the underlying byte slice.
// The caller should call Zero() when done.
func (s *SecureBytes) Bytes() []byte {
	return s.data
}

// Zero securely zeroes out the data and releases the slice.
func (s *SecureBytes) Zero() {
	if s.data != nil {
		ZeroBytes(s.data)
		s.data = nil
	}
}

// CopySecure creates a secure copy of the given bytes.
func CopySecure(src []byte) *SecureBytes {
	sb := NewSecureBytes(len(src))
	copy(sb.data, src)
	return sb
}
