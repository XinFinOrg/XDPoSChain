// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package tablewriter

import (
	"bytes"
	"strings"
	"testing"
)

func TestAppendRows(t *testing.T) {
	var buf bytes.Buffer
	table := NewWriter(&buf)

	table.SetHeader([]string{"A", "B"})
	table.Append([]string{"x", "y"})
	table.AppendBulk([][]string{{"p", "q"}})
	table.Render()

	output := buf.String()
	for _, want := range []string{"| x | y |", "| p | q |"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected %q in the rendered table:\n%s", want, output)
		}
	}
	if strings.Contains(output, "Error:") {
		t.Fatalf("valid rows rendered an error:\n%s", output)
	}
}

func TestRenderClosingBorder(t *testing.T) {
	separators := func(output string) int {
		count := 0
		for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
			if strings.HasPrefix(line, "+") && strings.HasSuffix(line, "+") {
				count++
			}
		}
		return count
	}
	tests := []struct {
		name   string
		footer []string
		want   int
	}{
		// Top border, border after the header, closing border.
		{"without footer", nil, 3},
		// Top border, border after the header, border before and after the footer.
		{"with footer", []string{"t", "u"}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			table := NewWriter(&buf)
			table.SetHeader([]string{"A", "B"})
			table.Append([]string{"x", "y"})
			if tt.footer != nil {
				table.SetFooter(tt.footer)
			}
			table.Render()

			output := buf.String()
			if got := separators(output); got != tt.want {
				t.Fatalf("expected %d separators, got %d:\n%s", tt.want, got, output)
			}
			lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
			if last := lines[len(lines)-1]; !strings.HasPrefix(last, "+") {
				t.Fatalf("table is not closed by a separator, last line is %q:\n%s", last, output)
			}
		})
	}
}

func TestRenderMultilineCell(t *testing.T) {
	var buf bytes.Buffer
	table := NewWriter(&buf)

	table.SetHeader([]string{"Server", "Address", "Value"})
	table.Append([]string{"srv", "first\nsecond", "v"})
	table.Append([]string{"srv2", "ok", "v2"})
	table.Render()

	output := buf.String()
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 lines, got %d:\n%s", len(lines), output)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "+") {
			continue
		}
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			t.Fatalf("cell content broke out of the table row: %q\n%s", line, output)
		}
	}
	if !strings.Contains(output, `first\nsecond`) {
		t.Fatalf("line break was not escaped:\n%s", output)
	}
}

func TestAppendColumnMismatch(t *testing.T) {
	var buf bytes.Buffer
	table := NewWriter(&buf)

	table.SetHeader([]string{"A", "B"})
	table.Append([]string{"x", "y", "z"})
	table.Render()

	output := buf.String()
	if !strings.Contains(output, "Error: row 0 has 3 columns, expected 2") {
		t.Fatalf("expected a column count error, got:\n%s", output)
	}
	if strings.Contains(output, "| x |") {
		t.Fatalf("a mismatched row was rendered anyway:\n%s", output)
	}
}
