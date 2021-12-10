# WHOIS Client

a simple Go WHOIS Client API.

## API
```go
Lookup(ctx context.Context, domain, server string) (string, error)
WHOISHost(domain string) (string, error)
TLDs() []string
```

## Install
`go get github.com/twiny/whois/v2`

## Example

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/twiny/whois/v2"
)

func main() {
	domain := "google.com"

	// to use Socks5 - this format 'socks5://username:password@alpha.hostname.com:1023'
	// otherwise use 'whois.Localhost' to use local connection
	client, err := whois.NewClient(whois.Localhost)
	if err != nil {
		fmt.Println(err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host, err := client.WHOISHost(domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	resp, err := client.Lookup(ctx, "google.com", host)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(resp)
	fmt.Println("done.")
}
```
## Tracking
- If you wish to add more WHOIS Server please [create a PR](https://github.com/twiny/whois/pulls).

- If you find any issues please [create a new issue](https://github.com/twiny/whois/issues/new).
