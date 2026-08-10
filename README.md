# go-libtab

A Go binding for the 9lx C `libtab` tabular database storage engine.

`go-libtab` exposes the C `libtab` implementation through cgo. The on-disk parser and table semantics come from plan9port `libndb`; cryptographic cell helpers use the bundled C Monocypher implementation.

## Features

- **Plan 9 Native (Text-First)**: Data is stored on disk in raw, space-continuation `ndb` attribute-value syntax. You can edit files with `vi`, inspect with `cat`, and query with `grep`.
- **Integrity Columns**:
  - `HASHED`: Cell values are irreversible digests (BLAKE2b or Argon2id).
  - `SIGNED`: Cell values carry a body + Monocypher EdDSA signature verified at load time.
- **In-Memory Querying**: Simple `Search(col, val)` over the C table iterator.
- **Atomic Commits**: Local persistence uses a write-to-tempfile, `fsync`, and atomic `rename` commit cycle.

## Requirements

- cgo enabled
- plan9port installed at `/usr/local/plan9`

## Installation

```bash
go get github.com/psilva261/go-libtab
```

## Example Usage

### 1. Creating a Table with Schema

```go
package main

import (
	"fmt"
	"github.com/psilva261/go-libtab"
)

func main() {
	cols := []libtab.Column{
		{Name: "user"},
		{Name: "uid"},
		{Name: "shell"},
	}

	table := libtab.Create("users.tab", "users", cols)

	// Add a row
	table.AddRow(map[string]string{
		"user":  "alice",
		"uid":   "1000",
		"shell": "/bin/rc",
	})

	// Commit changes atomically to users.tab
	table.Commit()
}
```

### 2. Loading and Querying a Table

```go
package main

import (
	"fmt"
	"github.com/psilva261/go-libtab"
)

func main() {
	table, _ := libtab.Open("users.tab")

	// Search for rows
	rows := table.Search("user", "alice")
	if len(rows) > 0 {
		alice := rows[0]
		fmt.Printf("UID: %s\n", alice.Values["uid"])
	}
}
```

### 3. Hash and Signature Cells

```go
hashCell, _ := libtab.HashArgon2id([]byte("secret123"))
ok, _ := libtab.VerifyHash(hashCell, []byte("secret123"))

pub, priv, _ := libtab.GenerateSigningKey()
signedCell, _ := libtab.SignBody([]byte("audit body"), priv)
body, _ := libtab.VerifySignature(signedCell, pub)
_, _ = ok, body
```
