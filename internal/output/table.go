package output

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// TableFormatter outputs human-readable tables
type TableFormatter struct{}

// Format implements the Formatter interface for table output
func (f *TableFormatter) Format(r Response) error {
	if r.Success {
		if r.Message != "" {
			fmt.Printf("✓ %s\n", r.Message)
		}
		if r.Data != nil {
			if err := printTable(r.Data); err != nil {
				return err
			}
		}
	} else {
		fmt.Printf("✗ Error: %s\n", r.Error)
	}

	// Print update warning
	if r.Update != nil && r.Update.Available {
		fmt.Printf("\n⚠ Update available: %s → %s\n", r.Update.CurrentVersion, r.Update.LatestVersion)
		fmt.Printf("  Run: %s\n", r.Update.Command)
	}

	// Print available actions
	if len(r.Actions) > 0 {
		fmt.Println("\nNext steps:")
		for _, a := range r.Actions {
			prefix := "→"
			if a.Dangerous {
				prefix = "⚠"
			}
			fmt.Printf("  %s %s\n", prefix, a.Description)
			fmt.Printf("    $ %s\n", a.Command)
		}
	}

	return nil
}

func printTable(data interface{}) error {
	if data == nil {
		return nil
	}

	switch v := data.(type) {
	case string:
		fmt.Println(v)
	case map[string]interface{}:
		printMapAsTable(v)
	case []interface{}:
		if len(v) == 0 {
			return nil
		}
		// Try to print as table if it's a slice of maps
		if isMapSlice(v) {
			printSliceAsTable(v)
		} else {
			// Fall back to simple list
			for _, item := range v {
				fmt.Printf("  • %v\n", item)
			}
		}
	default:
		// For complex types, use JSON as fallback
		b, err := json.MarshalIndent(data, "  ", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	}

	return nil
}

func printMapAsTable(m map[string]interface{}) {
	// Find max key length for alignment
	maxLen := 0
	for key := range m {
		if len(key) > maxLen {
			maxLen = len(key)
		}
	}

	// Print each key-value pair
	for key, val := range m {
		padding := strings.Repeat(" ", maxLen-len(key))
		fmt.Printf("  %s:%s %v\n", key, padding, formatValue(val))
	}
}

func printSliceAsTable(slice []interface{}) {
	if len(slice) == 0 {
		return
	}

	// Extract headers from first map
	first, ok := slice[0].(map[string]interface{})
	if !ok {
		return
	}

	headers := make([]string, 0, len(first))
	for key := range first {
		headers = append(headers, key)
	}

	// Calculate column widths
	widths := make(map[string]int)
	for _, header := range headers {
		widths[header] = len(header)
	}

	// Update widths based on data
	for _, item := range slice {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		for _, header := range headers {
			if val, exists := m[header]; exists {
				valStr := fmt.Sprintf("%v", val)
				if len(valStr) > widths[header] {
					widths[header] = len(valStr)
				}
			}
		}
	}

	// Print header row
	fmt.Print("  ")
	for _, header := range headers {
		fmt.Printf("%-*s  ", widths[header], header)
	}
	fmt.Println()

	// Print separator
	fmt.Print("  ")
	for _, header := range headers {
		fmt.Print(strings.Repeat("-", widths[header]) + "  ")
	}
	fmt.Println()

	// Print data rows
	for _, item := range slice {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		fmt.Print("  ")
		for _, header := range headers {
			val := m[header]
			fmt.Printf("%-*v  ", widths[header], formatValue(val))
		}
		fmt.Println()
	}
}

func isMapSlice(slice []interface{}) bool {
	if len(slice) == 0 {
		return false
	}
	_, ok := slice[0].(map[string]interface{})
	return ok
}

func formatValue(val interface{}) string {
	if val == nil {
		return ""
	}

	v := reflect.ValueOf(val)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		// Convert slice/array to comma-separated string
		parts := make([]string, v.Len())
		for i := 0; i < v.Len(); i++ {
			parts[i] = fmt.Sprintf("%v", v.Index(i).Interface())
		}
		return strings.Join(parts, ", ")
	case reflect.Map:
		// For maps, just show count
		return fmt.Sprintf("<%d items>", v.Len())
	default:
		return fmt.Sprintf("%v", val)
	}
}
