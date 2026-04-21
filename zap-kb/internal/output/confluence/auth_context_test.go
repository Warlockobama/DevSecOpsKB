package confluence

import (
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestOccurrenceAuthContext(t *testing.T) {
	cases := []struct {
		name string
		occ  *entities.Occurrence
		want string
	}{
		{"nil", nil, ""},
		{"no request", &entities.Occurrence{}, ""},
		{"empty headers", &entities.Occurrence{Request: &entities.HTTPRequest{}}, ""},
		{
			name: "cookie present",
			occ: &entities.Occurrence{Request: &entities.HTTPRequest{Headers: []entities.Header{
				{Name: "Cookie", Value: "session=abc; csrf=xyz"},
			}}},
			want: "Authenticated",
		},
		{
			name: "authorization bearer",
			occ: &entities.Occurrence{Request: &entities.HTTPRequest{Headers: []entities.Header{
				{Name: "Authorization", Value: "Bearer eyJhbGciOi..."},
			}}},
			want: "Authenticated",
		},
		{
			name: "x-csrf-token",
			occ: &entities.Occurrence{Request: &entities.HTTPRequest{Headers: []entities.Header{
				{Name: "X-CSRF-Token", Value: "abc"},
			}}},
			want: "Authenticated",
		},
		{
			name: "no auth headers but headers present",
			occ: &entities.Occurrence{Request: &entities.HTTPRequest{Headers: []entities.Header{
				{Name: "User-Agent", Value: "ZAP"},
				{Name: "Accept", Value: "text/html"},
			}}},
			want: "Unauthenticated",
		},
		{
			name: "authorization with non-bearer scheme is ignored",
			occ: &entities.Occurrence{Request: &entities.HTTPRequest{Headers: []entities.Header{
				{Name: "Authorization", Value: "Negotiate xyz"},
			}}},
			want: "Unauthenticated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := occurrenceAuthContext(tc.occ); got != tc.want {
				t.Errorf("occurrenceAuthContext = %q, want %q", got, tc.want)
			}
		})
	}
}
