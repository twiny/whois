# WHOIS Client

a simple Go WHOIS Client API.

## How it works
- split domain name and finds corresponded WHOIS DB server from `db.yaml`.
- dial a connection to the WHOIS server.
- save the response.

`whois.NewClient` function takes a `Dailer` argument.
```go
// Dialer
type Dialer interface {
    DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
```
using a `nil` arg to `whois.NewClient` will create a client using local connect.

## Install
`go get github.com/twiny/whois`

## Example
 - using local connection

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/twiny/whois"
)

func main() {
	client, err := whois.NewClient(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	text, err := client.Lookup(ctx, "google.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(text)
	fmt.Println("done.")
}
```

 - using SOCKS5 connection
```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/twiny/whois"
	"golang.org/x/net/proxy"
)

func main() {
	// create default client
	client, err := whois.NewClient(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// using SOCKS5
	// auth if required
	auth := &proxy.Auth{
		User:     "username",
		Password: "password",
	}
	dialer, err := proxy.SOCKS5("tcp", "hostname:port", auth, proxy.Direct)
	if err != nil {
		fmt.Println(err)
		return
	}

	// clone default client
	proxyClient, err := client.Clone(dialer)
	if err != nil {
		fmt.Println(err)
		return
	}

	// ctx
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	text, err := proxyClient.Lookup(ctx, "google.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(text)
	fmt.Println("done.")
}
```

## Tracking
- If you wish to add more WHOIS Server please [create a PR](https://github.com/twiny/whois/pulls).

- If you find any issues please [create a new issue](https://github.com/twiny/whois/issues/new).
