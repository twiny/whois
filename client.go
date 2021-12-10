package whois

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

var (
	testURL = "whois.verisign-grs.com:43" // TestURL
	// dialer
	forwrder = &net.Dialer{
		Timeout: 15 * time.Second,
	}
	//
	domainRegExp        = regexp.MustCompile(`(^(([[:alnum:]]-?)?([[:alnum:]]-?)+\.)+[A-Za-z]{2,20}$)`)
	Localhost    string = "socks5://localhost" // used for default client
	//go:embed db.yaml
	whoisdb []byte
)

// Client
type Client struct {
	socks  string
	db     map[string]string
	dialer func(network, addr string) (c net.Conn, err error)
}

// NewClient: a new WHOIS client using a Socks5 connection
// in this format: socks5://username:password@alpha.hostname.com:1023
// to use local connection pass `whois.Localhost` as argument.
func NewClient(socks5 string) (*Client, error) {
	// whois db
	db := map[string]string{}
	if err := yaml.Unmarshal(whoisdb, &db); err != nil {
		return nil, err
	}

	// if using local dialer
	if socks5 == Localhost {
		var d = &net.Dialer{}
		return &Client{
			socks:  socks5,
			db:     db,
			dialer: d.Dial,
		}, nil
	}

	d, err := socks5Dialer(socks5)
	if err != nil {
		return nil, err
	}

	return &Client{
		socks:  socks5,
		db:     db,
		dialer: d.Dial,
	}, nil
}

// Lookup a domain in a whois server db
func (c *Client) Lookup(ctx context.Context, domain, server string) (string, error) {
	// check if domain is domain
	name, tld, _, err := c.split(domain)
	if err != nil {
		return "", err
	}

	domain = name + "." + tld

	var text string
	result := make(chan string, 1)

	// lookup
	go func() {
		defer close(result)

		text, err = c.lookup(domain, server)
		result <- text
	}()

	// wait
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case text := <-result:
			if err != nil {
				return "", err
			}
			return text, nil
		}
	}
}

// lookup
func (c *Client) lookup(domain, server string) (string, error) {
	// WHOIS server address at port 43
	addr := net.JoinHostPort(server, "43")

	conn, err := c.dialer("tcp", addr)
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

	resp, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", err
	}

	if len(resp) == 0 {
		return "", fmt.Errorf("empty reponse")
	}

	return strings.Replace(string(resp), "\r", "", -1), nil
}

// Split domain name into 3 parts name, tld, server or an error
func (c *Client) WHOISHost(domain string) (string, error) {
	_, _, server, err := c.split(domain)
	if err != nil {
		return "", err
	}
	return server, nil
}

// split
func (c *Client) split(domain string) (name, tld, server string, err error) {
	domain = strings.ToLower(domain)

	// validate
	if !domainRegExp.MatchString(domain) {
		return "", "", "", fmt.Errorf("domain %s looks invalid", domain)
	}

	// extract TLD from domaian
	tld = publicsuffix.List.PublicSuffix(domain)

	// find whois host
	server, found := c.db[tld]
	if !found {
		return "", "", "", fmt.Errorf("could not find corresponded WHOIS server for %s", tld)
	}

	name = strings.TrimSuffix(domain, "."+tld)

	return
}

// TLDs
func (c *Client) TLDs() []string {
	var tlds = []string{}
	for tld := range c.db {
		tlds = append(tlds, tld)
	}
	return tlds
}

// socks5Dialer
func socks5Dialer(socks5 string) (proxy.Dialer, error) {
	surl, err := url.Parse(socks5)
	if err != nil {
		return nil, err
	}

	if surl.Scheme != "socks5" {
		return nil, errors.New("socks must start with socks5://")
	}

	// check auth
	username := surl.User.Username()
	password, found := surl.User.Password()

	auth := &proxy.Auth{}
	if username+password == "" && !found {
		auth = nil
	}

	d, err := proxy.SOCKS5("tcp", surl.Host, auth, forwrder)
	if err != nil {
		return nil, err
	}

	// to test connection
	conn, err := d.Dial("tcp", testURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return d, nil
}
