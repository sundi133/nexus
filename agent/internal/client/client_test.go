package client

import "testing"

func TestValidateServer(t *testing.T) {
	ok := []string{"https://api.nexus.votal.ai", "https://api.example.com/", "http://localhost:8080", "http://127.0.0.1:8080"}
	for _, s := range ok {
		if _, err := ValidateServer(s); err != nil {
			t.Errorf("%s: unexpected error %v", s, err)
		}
	}
	bad := []string{"http://api.example.com", "ftp://x", "not a url", "http://192.168.1.5:8080"}
	for _, s := range bad {
		if _, err := ValidateServer(s); err == nil {
			t.Errorf("%s: expected rejection", s)
		}
	}
}
