package libtab

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestAddRowScalesLinearly guards against AddRow rebuilding the whole Rows
// slice on every insert.
//
// The C library maintains its own index incrementally, so the binding should
// too. Rebuilding per insert makes n inserts cost O(n^2) allocations, which
// the C side cannot compensate for however fast its hash table is.
func TestAddRowScalesLinearly(t *testing.T) {
	insert := func(n int) time.Duration {
		path := filepath.Join(t.TempDir(), "scale.tab")
		tab := Create(path, "s", []Column{{Name: "k"}, {Name: "v"}})
		if tab == nil {
			t.Fatal("Create returned nil")
		}
		defer tab.Close()

		start := time.Now()
		for i := range n {
			if _, err := tab.AddRow(map[string]string{"k": fmt.Sprintf("key%d", i)}); err != nil {
				t.Fatalf("AddRow %d: %v", i, err)
			}
		}
		return time.Since(start)
	}

	small := insert(500)
	large := insert(2000)

	// Four times the rows should cost roughly four times as long. Quadratic
	// behaviour costs sixteen. Eight is comfortably between the two, so this
	// fails on O(n^2) without being brittle about scheduling noise.
	perRowSmall := float64(small.Nanoseconds()) / 500
	perRowLarge := float64(large.Nanoseconds()) / 2000
	ratio := perRowLarge / perRowSmall

	t.Logf("500 rows: %v (%.1f us/row)", small, perRowSmall/1000)
	t.Logf("2000 rows: %v (%.1f us/row)", large, perRowLarge/1000)
	t.Logf("per-row cost ratio: %.2fx", ratio)

	if ratio > 2.0 {
		t.Errorf("per-row cost grew %.2fx when the table grew 4x; AddRow is not linear", ratio)
	}
}

// TestAddRowKeepsRowsAccurate confirms the Rows slice still reflects the table
// after each insert, which is what the full reload was providing.
func TestAddRowKeepsRowsAccurate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rows.tab")
	tab := Create(path, "s", []Column{{Name: "k"}, {Name: "v"}})
	if tab == nil {
		t.Fatal("Create returned nil")
	}
	defer tab.Close()

	for i := range 5 {
		if _, err := tab.AddRow(map[string]string{
			"k": fmt.Sprintf("key%d", i),
			"v": fmt.Sprintf("val%d", i),
		}); err != nil {
			t.Fatalf("AddRow %d: %v", i, err)
		}
		if len(tab.Rows) != i+1 {
			t.Fatalf("after %d inserts Rows has %d entries", i+1, len(tab.Rows))
		}
	}

	// Every row must carry the values it was created with.
	for i, row := range tab.Rows {
		wantKey := fmt.Sprintf("key%d", i)
		if row.Values["k"] != wantKey {
			t.Errorf("Rows[%d] k = %q, want %q", i, row.Values["k"], wantKey)
		}
		if want := fmt.Sprintf("val%d", i); row.Values["v"] != want {
			t.Errorf("Rows[%d] v = %q, want %q", i, row.Values["v"], want)
		}
	}

	// A commit and reopen must agree with what the slice claimed.
	if err := tab.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()
	if len(reopened.Rows) != 5 {
		t.Errorf("reopened table has %d rows, want 5", len(reopened.Rows))
	}
}

// TestDeleteKeepsIndexConsistent guards the pointer index across removals.
// Delete rebuilds the slice, so the index must be rebuilt with it or a later
// insert would write at a stale position.
func TestDeleteKeepsIndexConsistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "del.tab")
	tab := Create(path, "s", []Column{{Name: "k"}, {Name: "v"}})
	if tab == nil {
		t.Fatal("Create returned nil")
	}
	defer tab.Close()

	for i := range 6 {
		if _, err := tab.AddRow(map[string]string{"k": fmt.Sprintf("key%d", i)}); err != nil {
			t.Fatal(err)
		}
	}

	if n := tab.Delete("k", "key2"); n != 1 {
		t.Fatalf("Delete removed %d rows, want 1", n)
	}
	if len(tab.Rows) != 5 {
		t.Fatalf("after delete Rows has %d entries, want 5", len(tab.Rows))
	}

	// Inserting after a delete must still land correctly.
	if _, err := tab.AddRow(map[string]string{"k": "key99"}); err != nil {
		t.Fatalf("AddRow after delete: %v", err)
	}
	if len(tab.Rows) != 6 {
		t.Fatalf("after reinsert Rows has %d entries, want 6", len(tab.Rows))
	}

	seen := map[string]bool{}
	for _, row := range tab.Rows {
		k := row.Values["k"]
		if seen[k] {
			t.Errorf("duplicate row %q in Rows", k)
		}
		seen[k] = true
	}
	if seen["key2"] {
		t.Error("deleted row is still in Rows")
	}
	if !seen["key99"] {
		t.Error("reinserted row is missing from Rows")
	}
}
