package whois

import (
	_ "embed"
	"errors"
	"sync"

	"gopkg.in/yaml.v2"
)

//go:embed db.yaml
var whoisdb []byte

// Errors
var (
	ErrDBServerEmpty     = errors.New("empty whois server database")
	ErrWHOISHostNotFound = errors.New("whois host not found")
)

// whoislist used for memory storage
type whoislist struct {
	mu    *sync.RWMutex
	table map[string]string
}

// newWhoisList
func newWhoisList() (*whoislist, error) {
	// whois config
	table := map[string]string{}
	if err := yaml.Unmarshal(whoisdb, &table); err != nil {
		return nil, err
	}

	if len(table) == 0 {
		return nil, ErrDBServerEmpty
	}
	return &whoislist{
		mu:    &sync.RWMutex{},
		table: table,
	}, nil
}

// Find: host, true
func (wl *whoislist) find(tld string) (string, bool) {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	//
	host, ok := wl.table[tld]
	if !ok {
		return "", false
	}
	return host, true
}
