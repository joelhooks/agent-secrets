package output

import (
	"encoding/json"
	"os"
)

// JSONFormatter outputs JSON format (agent-friendly)
type JSONFormatter struct{}

// Format implements the Formatter interface for JSON output
func (f *JSONFormatter) Format(r Response) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
