# DNS.LA for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/r6c/dnsla)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [DNS.LA](https://www.dns.la/), allowing you to manage DNS records.

## Features

- ✅ Get DNS records
- ✅ Create DNS records  
- ✅ Update DNS records
- ✅ Delete DNS records
- ✅ Support for A, AAAA, CNAME, TXT, MX, NS, SRV, CAA record types
- ✅ Compatible with libdns v1.1.0

## Installation

```bash
go get github.com/r6c/dnsla
```

## Usage

```go
package main

import (
    "context"
    "net/netip"
    "time"
    
    "github.com/libdns/libdns"
    "github.com/r6c/dnsla"
)

func main() {
    provider := dnsla.Provider{
        APIID:     "your-api-id",
        APISecret: "your-api-secret",
    }

    zone := "example.com."

    // Get records
    records, err := provider.GetRecords(context.TODO(), zone)
    if err != nil {
        panic(err)
    }

    // Add a new A record
    newRecords, err := provider.AppendRecords(context.TODO(), zone, []libdns.Record{
        libdns.Address{
            Name: "www",
            IP:   netip.MustParseAddr("192.168.1.1"),
            TTL:  10 * time.Minute,
        },
    })
    if err != nil {
        panic(err)
    }

    // Add a TXT record
    txtRecords, err := provider.AppendRecords(context.TODO(), zone, []libdns.Record{
        libdns.TXT{
            Name: "verification",
            Text: "your-verification-string",
            TTL:  10 * time.Minute,
        },
    })
    if err != nil {
        panic(err)
    }
}
```

## Authentication

You need to obtain API credentials from DNS.LA:

1. Log in to your DNS.LA account
2. Go to API settings
3. Generate an API ID and API Secret
4. Use these credentials in the Provider struct

## Testing

To run the tests, you need to set environment variables:

```bash
export DNSLA_API_ID="your-api-id"
export DNSLA_API_SECRET="your-api-secret"
export DNSLA_TEST_ZONE="your-test-domain.com"
go test -v
```

## Recent Updates

This package has been updated to be compatible with libdns v1.1.0, which introduced significant API changes:

### Changes Made:
- **Updated Record Handling**: Now uses the new libdns Record interface instead of the old Record struct
- **Type-Specific Records**: Returns concrete types like `libdns.Address`, `libdns.TXT`, etc.
- **Provider Data**: Uses the `ProviderData` field to store DNS.LA-specific record IDs
- **API Compatibility**: Fixed all API calls to work with the new libdns architecture

### Breaking Changes:
- The old `libdns.Record` struct is no longer used
- Record IDs are now stored in the `ProviderData` field
- Methods now work with the `libdns.Record` interface

## Supported Record Types

| DNS Record Type | libdns Type | Status |
|-----------------|-------------|---------|
| A               | `libdns.Address` | ✅ |
| AAAA            | `libdns.Address` | ✅ |
| CNAME           | `libdns.CNAME` | ✅ |
| TXT             | `libdns.TXT` | ✅ |
| MX              | `libdns.MX` | ✅ |
| NS              | `libdns.NS` | ✅ |
| SRV             | `libdns.SRV` | ✅ |
| CAA             | `libdns.CAA` | ✅ |

## API Documentation

For more information about the DNS.LA API, visit: https://www.dns.la/docs/ApiDoc

## License

This project is licensed under the MIT License.
