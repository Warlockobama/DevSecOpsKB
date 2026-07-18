package synccore

import "testing"

func TestAuthHeader(t *testing.T) {
	cases := []struct {
		name, user, token, want string
	}{
		{"basic", "user@example.com", "tok", "Basic dXNlckBleGFtcGxlLmNvbTp0b2s="},
		{"basic trims", " user@example.com ", " tok ", "Basic dXNlckBleGFtcGxlLmNvbTp0b2s="},
		{"bearer when no user", "", "pat-token", "Bearer pat-token"},
		{"bearer trims", "  ", " pat-token ", "Bearer pat-token"},
	}
	for _, tc := range cases {
		if got := AuthHeader(tc.user, tc.token); got != tc.want {
			t.Errorf("%s: AuthHeader(%q, %q) = %q, want %q", tc.name, tc.user, tc.token, got, tc.want)
		}
	}
}
