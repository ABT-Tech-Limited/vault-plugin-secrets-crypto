package backend

import (
	"regexp"
	"testing"
)

func TestValidateName_Colon(t *testing.T) {
	valid := []string{"my key", "my-key", "my_key", "ns:wallet", "a:b:c", "Key 01"}
	for _, n := range valid {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", n, err)
		}
	}
	invalid := []string{"", "with.dot", "with/slash", "with@at"}
	for _, n := range invalid {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) = nil, want error", n)
		}
	}
}

func TestValidateExternalID_Colon(t *testing.T) {
	valid := []string{"a", "user-123", "did:example:123", "ns:wallet:01", "a.b_c-d:e", "_lead", "trail_"}
	for _, id := range valid {
		if err := ValidateExternalID(id); err != nil {
			t.Errorf("ValidateExternalID(%q) = %v, want nil", id, err)
		}
	}
	// Besides invalid characters, external_id must start and end with a word
	// character, so leading/trailing dot, colon, or hyphen are rejected.
	invalid := []string{"", "with space", "with/slash", "with@at", ":foo", "foo:", ".foo", "foo.", "-foo", "foo-"}
	for _, id := range invalid {
		if err := ValidateExternalID(id); err == nil {
			t.Errorf("ValidateExternalID(%q) = nil, want error", id)
		}
	}
}

// TestExternalIDRouteRegex_Colon ensures value validation and URL route matching
// stay aligned: every external_id that validates must also match the route regex
// (so the key is reachable), and every external_id rejected for its shape must
// also fail to route (so no validated key can become unreachable).
func TestExternalIDRouteRegex_Colon(t *testing.T) {
	re := regexp.MustCompile("^" + externalIDRouteRegex("external_id") + "$")

	reachable := []string{"a", "user-123", "did:example:123", "ns:wallet:01", "a.b_c-d:e", "_lead", "trail_"}
	for _, id := range reachable {
		if err := ValidateExternalID(id); err != nil {
			t.Fatalf("precondition: ValidateExternalID(%q) = %v", id, err)
		}
		m := re.FindStringSubmatch(id)
		if m == nil {
			t.Errorf("route regex did not match %q (key would be unreachable)", id)
			continue
		}
		if got := m[re.SubexpIndex("external_id")]; got != id {
			t.Errorf("route regex captured %q, want %q", got, id)
		}
	}

	unroutable := []string{":foo", "foo:", ".foo", "foo.", "-foo", "foo-"}
	for _, id := range unroutable {
		if err := ValidateExternalID(id); err == nil {
			t.Errorf("ValidateExternalID(%q) = nil, want error", id)
		}
		if re.MatchString(id) {
			t.Errorf("route regex matched %q, but validation rejects it (rules drifted)", id)
		}
	}
}
