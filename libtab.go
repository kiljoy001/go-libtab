package libtab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Column struct {
	Name  string
	Type  string            // "HASHED", "SIGNED", or ""
	Attrs map[string]string // e.g. algo -> argon2id
}

type Schema struct {
	Name    string
	Columns []Column
	ColMap  map[string]Column
}

type Row struct {
	Values map[string]string // colName -> raw cell value (includes type prefix if typed)
}

type Table struct {
	Path   string
	Schema Schema
	Rows   []*Row
	dirty  bool
}

func B64Encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func B64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if dec, err := base64.URLEncoding.DecodeString(s); err == nil {
		return dec, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func parseNDBLine(line string) map[string]string {
	attrs := make(map[string]string)
	var tokens []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if (ch == ' ' || ch == '\t') && !inQuotes {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	for _, token := range tokens {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) == 2 {
			attrs[parts[0]] = parts[1]
		} else {
			attrs[parts[0]] = ""
		}
	}
	return attrs
}

func parseNDB(r io.Reader) ([][]map[string]string, error) {
	scanner := bufio.NewScanner(r)
	var tuples [][]map[string]string
	var currentTuple []map[string]string

	finishTuple := func() {
		if len(currentTuple) > 0 {
			tuples = append(tuples, currentTuple)
			currentTuple = nil
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if trimmed == "" {
				finishTuple()
			}
			continue
		}

		isContinuation := line[0] == ' ' || line[0] == '\t'
		attrs := parseNDBLine(trimmed)

		if isContinuation {
			if len(currentTuple) == 0 {
				return nil, fmt.Errorf("unexpected continuation line: %q", line)
			}
			currentTuple = append(currentTuple, attrs)
		} else {
			finishTuple()
			currentTuple = append(currentTuple, attrs)
		}
	}
	finishTuple()

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tuples, nil
}

func parseSchema(tuple []map[string]string) (Schema, error) {
	if len(tuple) == 0 {
		return Schema{}, fmt.Errorf("empty schema tuple")
	}

	var schemaName string
	for _, m := range tuple {
		if val, ok := m["schema"]; ok {
			schemaName = val
			break
		}
	}
	if schemaName == "" {
		return Schema{}, fmt.Errorf("first tuple must declare schema=<name>")
	}

	schema := Schema{
		Name:   schemaName,
		ColMap: make(map[string]Column),
	}

	for _, m := range tuple {
		colName, ok := m["col"]
		if !ok {
			continue
		}
		colType := m["type"]
		attrs := make(map[string]string)
		for k, v := range m {
			if k != "col" && k != "type" {
				attrs[k] = v
			}
		}
		column := Column{
			Name:  colName,
			Type:  colType,
			Attrs: attrs,
		}
		schema.Columns = append(schema.Columns, column)
		schema.ColMap[colName] = column
	}

	if len(schema.Columns) == 0 {
		return Schema{}, fmt.Errorf("schema must declare at least one column")
	}
	return schema, nil
}

func flattenTuple(tuple []map[string]string) map[string]string {
	flat := make(map[string]string)
	for _, m := range tuple {
		for k, v := range m {
			flat[k] = v
		}
	}
	return flat
}

func (s *Schema) ValidateRow(attrs map[string]string) (*Row, error) {
	row := &Row{Values: make(map[string]string)}
	for k, v := range attrs {
		col, ok := s.ColMap[k]
		if !ok {
			return nil, fmt.Errorf("unknown column %q in row", k)
		}
		if col.Type != "" && v != "" {
			expectedTag := strings.ToLower(col.Type) + ":"
			if !strings.HasPrefix(v, expectedTag) {
				return nil, fmt.Errorf("cell %q must start with tag %q", k, expectedTag)
			}
		}
		row.Values[k] = v
	}
	for _, col := range s.Columns {
		if _, ok := row.Values[col.Name]; !ok {
			row.Values[col.Name] = ""
		}
	}
	return row, nil
}

func Open(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tuples, err := parseNDB(f)
	if err != nil {
		return nil, err
	}

	if len(tuples) == 0 {
		return nil, fmt.Errorf("empty libtab file")
	}

	schema, err := parseSchema(tuples[0])
	if err != nil {
		return nil, err
	}

	table := &Table{
		Path:   path,
		Schema: schema,
	}

	for i := 1; i < len(tuples); i++ {
		flat := flattenTuple(tuples[i])
		row, err := schema.ValidateRow(flat)
		if err != nil {
			return nil, fmt.Errorf("row %d validation failed: %v", i, err)
		}
		table.Rows = append(table.Rows, row)
	}

	return table, nil
}

func Create(path, schemaName string, columns []Column) *Table {
	colMap := make(map[string]Column)
	for _, col := range columns {
		colMap[col.Name] = col
	}
	return &Table{
		Path: path,
		Schema: Schema{
			Name:    schemaName,
			Columns: columns,
			ColMap:  colMap,
		},
		dirty: true,
	}
}

func (t *Table) AddRow(values map[string]string) (*Row, error) {
	row, err := t.Schema.ValidateRow(values)
	if err != nil {
		return nil, err
	}
	t.Rows = append(t.Rows, row)
	t.dirty = true
	return row, nil
}

func (t *Table) Search(col, val string) []*Row {
	var results []*Row
	for _, r := range t.Rows {
		if r.Values[col] == val {
			results = append(results, r)
		}
	}
	return results
}

func (t *Table) Delete(col, val string) int {
	var count int
	var remaining []*Row
	for _, r := range t.Rows {
		if r.Values[col] == val {
			count++
			t.dirty = true
		} else {
			remaining = append(remaining, r)
		}
	}
	t.Rows = remaining
	return count
}

func escapeValue(val string) string {
	if strings.ContainsAny(val, " \t\n\r\"") {
		escaped := strings.ReplaceAll(val, "\"", "\\\"")
		return "\"" + escaped + "\""
	}
	return val
}

func (t *Table) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("schema=%s\n", t.Schema.Name))
	for _, col := range t.Schema.Columns {
		buf.WriteString(fmt.Sprintf("\tcol=%s", col.Name))
		if col.Type != "" {
			buf.WriteString(fmt.Sprintf(" type=%s", col.Type))
		}
		var attrs []string
		for k := range col.Attrs {
			attrs = append(attrs, k)
		}
		sort.Strings(attrs)
		for _, k := range attrs {
			buf.WriteString(fmt.Sprintf(" %s=%s", k, col.Attrs[k]))
		}
		buf.WriteString("\n")
	}
	buf.WriteString("\n")

	headCol := t.Schema.Columns[0].Name
	for _, row := range t.Rows {
		buf.WriteString(fmt.Sprintf("%s=%s\n", headCol, escapeValue(row.Values[headCol])))
		for _, col := range t.Schema.Columns {
			if col.Name == headCol {
				continue
			}
			val := row.Values[col.Name]
			if val != "" {
				buf.WriteString(fmt.Sprintf("\t%s=%s\n", col.Name, escapeValue(val)))
			}
		}
		buf.WriteString("\n")
	}

	return buf.Bytes(), nil
}

func (t *Table) Commit() error {
	if !t.dirty {
		return nil
	}

	data, err := t.Serialize()
	if err != nil {
		return err
	}

	dir := filepath.Dir(t.Path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	tmpFile, err := os.CreateTemp(dir, "libtab-commit-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, t.Path); err != nil {
		return err
	}

	t.dirty = false
	return nil
}
