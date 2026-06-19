# go-libtab

A pure Go port of the 9lx `libtab` tabular database storage engine.

`go-libtab` implements a schema-agnostic, typed-table storage substrate built on top of Plan 9's native `ndb` (network database) syntax. It guarantees human inspectability on disk while adding optional cryptographic columns (`HASHED` and `SIGNED`) for cell-level integrity.

## Features

- **Plan 9 Native (Text-First)**: Data is stored on disk in raw, space-continuation `ndb` attribute-value syntax. You can edit files with `vi`, inspect with `cat`, and query with `grep`.
- **Integrity Columns**:
  - `HASHED`: Cell values are irreversible digests (BLAKE2b or Argon2id).
  - `SIGNED`: Cell values carry a body + Ed25519 signature verified at load time.
- **In-Memory Querying**: Fast `O(1)` linear lookup using simple `Search(col, val)` and iterator APIs.
- **Atomic Commits**: Persistence uses a standard write-to-tempfile, `fsync`, and atomic `rename` commit cycle.

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
		{Name: "pwhash", Type: "HASHED", Attrs: map[string]string{"algo": "argon2id"}},
	}

	table := libtab.Create("users.tab", "users", cols)

	// Hash password preimage
	pwHash, _ := libtab.HashArgon2id([]byte("secret123"))

	// Add a row
	table.AddRow(map[string]string{
		"user":   "alice",
		"uid":    "1000",
		"pwhash": pwHash,
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

		// Verify hashed column preimage
		ok, _ := libtab.VerifyHash(alice.Values["pwhash"], []byte("secret123"))
		if ok {
			fmt.Println("Password is correct!")
		}
	}
}
```
