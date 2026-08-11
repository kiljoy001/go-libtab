package libtab

/*
#cgo CFLAGS: -DPLAN9PORT -I${SRCDIR}/clibtab -I${SRCDIR} -I/usr/local/plan9/include
#cgo LDFLAGS: -L/usr/local/plan9/lib -lndb -lbio -l9 -lpthread -lm

#include <stdlib.h>
static void go_libtab_std_free(void *p) { free(p); }

#include <u.h>
#include <libc.h>
#include "libtab.h"

extern char *tab_serialize(Tab *t, int *outlen);
static void go_libtab_p9_free(void *p) { p9free(p); }
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
)

type Column struct {
	Name  string
	Type  string
	Attrs map[string]string
}

type Schema struct {
	Name    string
	Columns []Column
	ColMap  map[string]Column
}

type Row struct {
	Values map[string]string
	ptr    *C.TabRow
}

type Table struct {
	Path   string
	Schema Schema
	Rows   []*Row

	ptr *C.Tab

	// byPtr maps a C row to its position in Rows, so an insert does not have
	// to scan the slice to find out whether the row is already there.
	byPtr map[*C.TabRow]int
}

func lastError() error {
	return fmt.Errorf("%s", C.GoString(C.tab_lasterror()))
}

func cString(s string) *C.char {
	return C.CString(s)
}

func freeCString(s *C.char) {
	if s != nil {
		C.go_libtab_std_free(unsafe.Pointer(s))
	}
}

func freePlan9(p unsafe.Pointer) {
	if p != nil {
		C.go_libtab_p9_free(p)
	}
}

func B64Encode(data []byte) string {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}

	out := C.tab_b64_encode(in, C.int(len(data)))
	if out == nil {
		return ""
	}
	defer freePlan9(unsafe.Pointer(out))
	return C.GoString(out)
}

func B64Decode(s string) ([]byte, error) {
	cs := cString(s)
	defer freeCString(cs)

	var outLen C.int
	out := C.tab_b64_decode(cs, &outLen)
	if out == nil {
		return nil, lastError()
	}
	defer freePlan9(unsafe.Pointer(out))

	return C.GoBytes(unsafe.Pointer(out), outLen), nil
}

func Open(path string) (*Table, error) {
	cpath := cString(path)
	defer freeCString(cpath)

	ptr := C.tab_open(cpath)
	if ptr == nil {
		return nil, lastError()
	}

	t := &Table{Path: path, ptr: ptr}
	runtime.SetFinalizer(t, (*Table).Close)

	if err := t.loadSchema(); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.reloadRows(); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func Create(path, schemaName string, columns []Column) *Table {
	if len(columns) == 0 {
		return nil
	}

	cpath := cString(path)
	cschema := cString(schemaName)
	defer freeCString(cpath)
	defer freeCString(cschema)

	specs := make([]C.TabColSpec, len(columns))
	for i, col := range columns {
		cname := cString(col.Name)
		specs[i].name = cname
		defer freeCString(cname)

		if col.Type != "" {
			ctype := cString(col.Type)
			specs[i]._type = ctype
			defer freeCString(ctype)
		}
		if col.Attrs != nil {
			if algo := col.Attrs["algo"]; algo != "" {
				calgo := cString(algo)
				specs[i].algo = calgo
				defer freeCString(calgo)
			}
			if signer := col.Attrs["signer"]; signer != "" {
				csigner := cString(signer)
				specs[i].signer = csigner
				defer freeCString(csigner)
			}
		}
	}

	ptr := C.tab_create(cpath, cschema, &specs[0], C.int(len(specs)))
	if ptr == nil {
		return nil
	}

	t := &Table{Path: path, ptr: ptr}
	runtime.SetFinalizer(t, (*Table).Close)
	if err := t.loadSchema(); err != nil {
		t.Close()
		return nil
	}
	_ = t.reloadRows()
	return t
}

func (t *Table) AddRow(values map[string]string) (*Row, error) {
	if t == nil || t.ptr == nil {
		return nil, fmt.Errorf("closed table")
	}
	if len(t.Schema.Columns) == 0 {
		return nil, fmt.Errorf("table has no schema columns")
	}

	head := t.Schema.Columns[0].Name
	headVal := values[head]
	if headVal == "" {
		return nil, fmt.Errorf("head column %q must not be empty", head)
	}

	chead := cString(head)
	cval := cString(headVal)
	defer freeCString(chead)
	defer freeCString(cval)

	rowPtr := C.tab_add_row(t.ptr, chead, cval)
	if rowPtr == nil {
		return nil, lastError()
	}

	row := t.rowFromPtr(rowPtr)
	for _, col := range t.Schema.Columns {
		if col.Name == head {
			continue
		}
		value, ok := values[col.Name]
		if !ok || value == "" {
			continue
		}
		if col.Type != "" {
			return nil, fmt.Errorf("typed column %q must be set with a typed setter", col.Name)
		}
		if err := t.Set(row, col.Name, value); err != nil {
			return nil, err
		}
	}
	/*
	 * The C library maintains its own index as rows arrive, so the Go-side
	 * slice only needs the new row appended. Rebuilding it here made n
	 * inserts cost O(n^2): every AddRow walked the whole table and
	 * allocated a Row, with a cgo call per column, for every existing row.
	 */
	fresh := t.rowFromPtr(rowPtr)
	if existing := t.rowIndexOf(rowPtr); existing >= 0 {
		// tab_add_row is idempotent for an identical row, so a repeated
		// add updates in place rather than growing the slice.
		t.Rows[existing] = fresh
	} else {
		if t.byPtr == nil {
			t.byPtr = make(map[*C.TabRow]int, len(t.Rows)+1)
		}
		t.byPtr[rowPtr] = len(t.Rows)
		t.Rows = append(t.Rows, fresh)
	}
	return fresh, nil
}

// rowIndexOf reports where a C row sits in the Rows slice, or -1.
func (t *Table) rowIndexOf(ptr *C.TabRow) int {
	if t.byPtr == nil {
		return -1
	}
	if i, ok := t.byPtr[ptr]; ok {
		return i
	}
	return -1
}

func (t *Table) Set(row *Row, col, value string) error {
	if t == nil || t.ptr == nil || row == nil || row.ptr == nil {
		return fmt.Errorf("closed table or row")
	}

	ccol := cString(col)
	cval := cString(value)
	defer freeCString(ccol)
	defer freeCString(cval)

	if C.tab_set(t.ptr, row.ptr, ccol, cval) < 0 {
		return lastError()
	}
	row.Values[col] = value
	return nil
}

func (t *Table) Search(col, val string) []*Row {
	if t == nil || t.ptr == nil {
		return nil
	}

	ccol := cString(col)
	cval := cString(val)
	defer freeCString(ccol)
	defer freeCString(cval)

	it := C.tab_search(t.ptr, ccol, cval)
	if it == nil {
		return nil
	}
	defer C.tab_iter_close(it)

	var rows []*Row
	byPtr := make(map[*C.TabRow]int)
	for {
		rowPtr := C.tab_iter_next(it)
		if rowPtr == nil {
			break
		}
		byPtr[rowPtr] = len(rows)
		rows = append(rows, t.rowFromPtr(rowPtr))
	}
	t.byPtr = byPtr
	return rows
}

func (t *Table) Delete(col, val string) int {
	rows := t.Search(col, val)
	deleted := 0
	for _, row := range rows {
		if C.tab_remove_row(t.ptr, row.ptr) == 0 {
			deleted++
		}
	}
	_ = t.reloadRows()
	return deleted
}

func (t *Table) Serialize() ([]byte, error) {
	if t == nil || t.ptr == nil {
		return nil, fmt.Errorf("closed table")
	}

	var outLen C.int
	out := C.tab_serialize(t.ptr, &outLen)
	if out == nil {
		return nil, lastError()
	}
	defer freePlan9(unsafe.Pointer(out))

	return C.GoBytes(unsafe.Pointer(out), outLen), nil
}

func (t *Table) Commit() error {
	if t == nil || t.ptr == nil {
		return fmt.Errorf("closed table")
	}

	dir := filepath.Dir(t.Path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if C.tab_commit(t.ptr) < 0 {
		return lastError()
	}
	return nil
}

func (t *Table) Close() {
	if t == nil || t.ptr == nil {
		return
	}
	C.tab_close(t.ptr)
	t.ptr = nil
	runtime.SetFinalizer(t, nil)
}

func (t *Table) loadSchema() error {
	name := C.tab_schema_name(t.ptr)
	if name == nil {
		return lastError()
	}

	ncols := int(C.tab_ncolumns(t.ptr))
	schema := Schema{
		Name:    C.GoString(name),
		Columns: make([]Column, 0, ncols),
		ColMap:  make(map[string]Column, ncols),
	}

	for i := 0; i < ncols; i++ {
		cname := C.tab_colname(t.ptr, C.int(i))
		if cname == nil {
			return lastError()
		}
		col := Column{
			Name:  C.GoString(cname),
			Attrs: make(map[string]string),
		}
		if ctype := C.tab_coltype(t.ptr, C.int(i)); ctype != nil {
			col.Type = C.GoString(ctype)
		}
		for _, key := range []string{"algo", "signer"} {
			ckey := cString(key)
			ccol := cString(col.Name)
			attr := C.tab_col_attr(t.ptr, ccol, ckey)
			freeCString(ckey)
			freeCString(ccol)
			if attr != nil {
				col.Attrs[key] = C.GoString(attr)
			}
		}
		if len(col.Attrs) == 0 {
			col.Attrs = nil
		}
		schema.Columns = append(schema.Columns, col)
		schema.ColMap[col.Name] = col
	}

	t.Schema = schema
	return nil
}

func (t *Table) reloadRows() error {
	it := C.tab_iter(t.ptr)
	if it == nil {
		return lastError()
	}
	defer C.tab_iter_close(it)

	var rows []*Row
	byPtr := make(map[*C.TabRow]int)
	for {
		rowPtr := C.tab_iter_next(it)
		if rowPtr == nil {
			break
		}
		byPtr[rowPtr] = len(rows)
		rows = append(rows, t.rowFromPtr(rowPtr))
	}
	t.byPtr = byPtr
	t.Rows = rows
	return nil
}

func (t *Table) rowFromPtr(rowPtr *C.TabRow) *Row {
	row := &Row{
		Values: make(map[string]string, len(t.Schema.Columns)),
		ptr:    rowPtr,
	}
	for _, col := range t.Schema.Columns {
		ccol := cString(col.Name)
		val := C.tab_get(rowPtr, ccol)
		freeCString(ccol)
		if val == nil {
			row.Values[col.Name] = ""
			continue
		}
		row.Values[col.Name] = C.GoString(val)
	}
	return row
}
