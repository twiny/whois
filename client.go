package whois

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Errors
var (
	ErrEmptyResponse    = errors.New("empty whois response")
	ErrBadDialer        = errors.New("bad dialer")
	ErrConnectionFailed = errors.New("could not establish connection")
	ErrTimeout          = errors.New("timeout")
)

// used for default client
var localDialer = net.Dialer{}

// Dialer
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Client
type Client struct {
	dialer Dialer
	db     *whoislist
}

// NewClient
func NewClient(dialer Dialer) (*Client, error) {
	// use local dialer
	if dialer == nil {
		dialer = &localDialer
	}

	db, err := newWhoisList()
	if err != nil {
		return nil, err
	}

	return &Client{
		dialer: dialer,
		db:     db,
	}, nil
}

// Clone
func (c *Client) Clone(dialer interface{}) (*Client, error) {
	d, ok := dialer.(Dialer)
	if !ok {
		return nil, ErrBadDialer
	}

	return &Client{
		dialer: d,
		db:     c.db,
	}, nil
}

// Split
func (c *Client) Split(domain string) (name, tld, host string, err error) {
	// to lower
	domain = strings.ToLower(domain)

	// extract TLD from domaian
	tld = publicsuffix.List.PublicSuffix(domain)
	name = strings.TrimSuffix(domain, "."+tld)

	// find whois host
	host, found := c.db.find(tld)
	if !found {
		return "", "", "", ErrWHOISHostNotFound
	}
	return
}

// lookupHost
func (c *Client) lookupHost(ctx context.Context, domain, host string) (string, error) {
	domain = strings.ToLower(domain)

	// connect
	addr := net.JoinHostPort(host, "43")

	conn, err := c.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", ErrConnectionFailed
	}
	defer conn.Close()

	var buff bytes.Buffer
	buff.WriteString(domain)
	buff.WriteString("\r\n")

	if _, err := conn.Write(buff.Bytes()); err != nil {
		return "", err
	}

	resp, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", err
	}
	if len(resp) == 0 {
		return "", ErrEmptyResponse
	}
	text := strings.Replace(string(resp), "\r", "", -1)

	return text, nil
}

// LookupHost
func (c *Client) LookupHost(ctx context.Context, domain, host string) (string, error) {
	return c.lookupHost(ctx, domain, host)
}

// Lookup
func (c *Client) Lookup(ctx context.Context, domain string) (string, error) {
	var (
		err error
		s   string
	)

	// split
	name, tld, host, err := c.Split(domain)
	if err != nil {
		return "", err
	}

	// to lowercase domain
	domain = name + "." + tld

	text := make(chan string, 1)
	go func() {
		defer close(text)

		// lookup
		s, err = c.lookupHost(ctx, domain, host)
		text <- s
	}()

	for {
		select {
		case <-ctx.Done():
			return "", ErrTimeout
		case s := <-text:
			if err != nil {
				return "", err
			}
			return s, nil
		}
	}
}

// WHOISList
func (c *Client) WHOISList() map[string]string {
	c.db.mu.RLock()
	defer c.db.mu.RUnlock()

	return c.db.table
}
