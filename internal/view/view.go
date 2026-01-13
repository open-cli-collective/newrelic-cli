package view

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// Format represents the output format type
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatPlain Format = "plain"
)

// ValidFormats contains all valid output formats
var ValidFormats = []Format{FormatTable, FormatJSON, FormatPlain}

// ValidateFormat checks if a format string is valid
func ValidateFormat(f string) error {
	switch Format(f) {
	case FormatTable, FormatJSON, FormatPlain:
		return nil
	default:
		return fmt.Errorf("invalid output format %q: must be one of table, json, plain", f)
	}
}

// View handles output rendering
type View struct {
	Out     io.Writer
	ErrOut  io.Writer
	Format  Format
	NoColor bool
}

// New creates a new View with defaults
func New(out, errOut io.Writer) *View {
	return &View{
		Out:     out,
		ErrOut:  errOut,
		Format:  FormatTable,
		NoColor: false,
	}
}

// Default creates a View using stdout and stderr
func Default() *View {
	return New(os.Stdout, os.Stderr)
}

// Table renders data as an aligned table
func (v *View) Table(headers []string, rows [][]string) error {
	if len(rows) == 0 {
		return nil
	}

	w := tabwriter.NewWriter(v.Out, 0, 0, 2, ' ', 0)

	// Print headers
	if v.NoColor {
		fmt.Fprintln(w, strings.Join(headers, "\t"))
	} else {
		bold := color.New(color.Bold)
		headerStrs := make([]string, len(headers))
		for i, h := range headers {
			headerStrs[i] = bold.Sprint(h)
		}
		fmt.Fprintln(w, strings.Join(headerStrs, "\t"))
	}

	// Print rows
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	return w.Flush()
}

// JSON renders data as formatted JSON
func (v *View) JSON(data interface{}) error {
	enc := json.NewEncoder(v.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// Plain renders rows as tab-separated values without headers
func (v *View) Plain(rows [][]string) error {
	for _, row := range rows {
		fmt.Fprintln(v.Out, strings.Join(row, "\t"))
	}
	return nil
}

// Print writes a message to stdout
func (v *View) Print(format string, args ...interface{}) {
	fmt.Fprintf(v.Out, format, args...)
}

// Println writes a message to stdout with newline
func (v *View) Println(a ...interface{}) {
	fmt.Fprintln(v.Out, a...)
}

// Success prints a success message (green if colors enabled)
func (v *View) Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if v.NoColor {
		fmt.Fprintln(v.ErrOut, msg)
	} else {
		color.New(color.FgGreen).Fprintln(v.ErrOut, msg)
	}
}

// Error prints an error message (red if colors enabled)
func (v *View) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if v.NoColor {
		fmt.Fprintln(v.ErrOut, msg)
	} else {
		color.New(color.FgRed).Fprintln(v.ErrOut, msg)
	}
}

// Warning prints a warning message (yellow if colors enabled)
func (v *View) Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if v.NoColor {
		fmt.Fprintln(v.ErrOut, msg)
	} else {
		color.New(color.FgYellow).Fprintln(v.ErrOut, msg)
	}
}

// Render automatically chooses output format based on View.Format
func (v *View) Render(headers []string, rows [][]string, data interface{}) error {
	switch v.Format {
	case FormatJSON:
		return v.JSON(data)
	case FormatPlain:
		return v.Plain(rows)
	default:
		return v.Table(headers, rows)
	}
}

// Truncate shortens a string to max length with ellipsis
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
