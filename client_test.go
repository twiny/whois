package whois

import "testing"

func TestSplit(t *testing.T) {
	var cases = []struct {
		in   string
		name string
		tld  string
		err  bool
	}{
		{"google.com", "google", "com", false},
		{" google.com.", "", "", true},
		{"www.google.com", "google", "com", false},
		{"www.go-ogle.com.", "", "", true},
		{"www.go-ogle.com", "go-ogle", "com", false},
		{"host.alpha.host.www.google.com", "google", "com", false},
	}

	client, err := NewClient(nil)
	if err != nil {
		t.Errorf("NewClient() == %s, want 'nil'", err)
	}

	for _, c := range cases {
		name, tld, _, err := client.split(c.in)
		if err != nil && !c.err {
			t.Errorf("split(%s) == %s, want 'nil'", c.in, err)
		}

		if name != c.name {
			t.Errorf("split(%q) == %q, want %q", c.in, name, c.name)
		}

		if tld != c.tld {
			t.Errorf("split(%q) == %q, want %q", c.in, tld, c.tld)
		}
	}
}
