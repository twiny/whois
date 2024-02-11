# WHOIS Client

a simple Go WHOIS Client API. It supports custom `proxy.Dialer` for Socks5.

## API

```go
Query(ctx context.Context, domain string) (Response, error)
```

## Install

`go get github.com/twiny/whois/v2`

## Example

```go
package main

import (
 "context"
 "fmt"

 "github.com/twiny/whois/v2"
)

func main() {
 client, err := whois.NewClient(nil)
 if err != nil {
  fmt.Printf("err: %s\n", err)
 }

 resp, err := client.Query(context.TODO(), "google.com")
 if err != nil {
  fmt.Printf("err: %s\n", err)
 }

 // Print the response
 fmt.Printf("Domain: %+v\n", resp)
}
```

## Tracking

- If you wish to add more WHOIS Server please [create a PR](https://github.com/twiny/whois/pulls).

- If you find any issues please [create a new issue](https://github.com/twiny/whois/issues/new).
