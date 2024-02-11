package whois

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

var (
	//go:embed db.yaml
	whoisdb []byte

	domainRegExp = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})$`)

	defaultDialer = &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
)

type (
	Client struct {
		dialer proxy.Dialer
		db     map[string]string
	}

	Response struct {
		Domain    string
		Name      string
		TLD       string
		WHOISHost string
		WHOISRaw  string
	}
)

// NewClient: create a new WHOIS client, if dialer is nil, it will use the default dialer
func NewClient(dialer proxy.Dialer) (*Client, error) {
	var db = map[string]string{}
	if err := yaml.Unmarshal(whoisdb, &db); err != nil {
		return nil, err
	}

	if dialer == nil {
		dialer = defaultDialer
	}

	return &Client{
		db:     db,
		dialer: dialer,
	}, nil
}

// Query: return raw WHOIS information for a domain
func (c *Client) Query(ctx context.Context, domain string) (Response, error) {
	var response Response
	name, tld, whoisHost, err := c.split(domain)
	if err != nil {
		return response, err
	}

	domain = strings.Join([]string{name, tld}, ".")

	var (
		text      string
		lookupErr error
		result    = make(chan string, 1)
	)

	go func() {
		defer close(result)

		text, lookupErr = c.lookup(domain, whoisHost)
		result <- text
	}()

	for {
		select {
		case <-ctx.Done():
			return response, ctx.Err()
		case text := <-result:
			if lookupErr != nil {
				return response, err
			}

			response.Domain = domain
			response.Name = name
			response.TLD = tld
			response.WHOISHost = whoisHost
			response.WHOISRaw = text

			return response, nil
		}
	}
}

func (c *Client) lookup(domain, whoisHost string) (string, error) {
	addr := net.JoinHostPort(whoisHost, "43") // WHOIS server address at port 43

	conn, err := c.dialer.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	var buff bytes.Buffer
	buff.WriteString(domain)
	buff.WriteString("\r\n")

	if _, err := conn.Write(buff.Bytes()); err != nil {
		return "", err
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}

	if len(resp) == 0 {
		return "", fmt.Errorf("empty reponse")
	}

	return strings.Replace(string(resp), "\r", "", -1), nil
}

// split: validate and split domain: name, tld, server or error
func (c *Client) split(raw string) (string, string, string, error) {
	if !domainRegExp.MatchString(raw) {
		return "", "", "", fmt.Errorf("invalid domain: %s", raw)
	}

	tld, icann := publicsuffix.PublicSuffix(raw)
	if !icann {
		return "", "", "", fmt.Errorf("unsupported TLD: %s", tld)
	}

	server, found := c.db[tld]
	if !found {
		return "", "", "", fmt.Errorf("unsupported TLD: %s", tld)
	}

	trimmedDomain := strings.TrimSuffix(raw, "."+tld)

	// Split the raw domain into parts.
	// e.g. www.google.com -> www.google -> google
	// If no parts, the trimmed domain itself is the name.
	// Otherwise, the name is the last part in array.
	parts := strings.Split(trimmedDomain, ".")

	var name string
	if len(parts) == 0 {
		name = trimmedDomain
	} else {
		name = parts[len(parts)-1]
	}

	return name, tld, server, nil
}
