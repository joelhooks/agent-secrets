package output

import (
	"fmt"
	"reflect"
	"strings"
)

// RawFormatter outputs just values (for piping and scripts)
type RawFormatter struct{}

// Format implements the Formatter interface for raw output
func (f *RawFormatter) Format(r Response) error {
	// For raw mode, only output the actual data
	// Ignore success/error markers, actions, and other metadata
	if r.Data != nil {
		return printRaw(r.Data)
	}

	// If no data but there's an error, output the error message
	if !r.Success && r.Error != "" {
		fmt.Println(r.Error)
	}

	return nil
}

func printRaw(data interface{}) error {
	if data == nil {
		return nil
	}

	switch v := data.(type) {
	case string:
		// Just the string value
		fmt.Println(v)
	case map[string]interface{}:
		// Output map values one per line
		for _, val := range v {
			fmt.Println(formatRawValue(val))
		}
	case []interface{}:
		// Output slice items one per line
		for _, item := range v {
			fmt.Println(formatRawValue(item))
		}
	default:
		// For other types, use default formatting
		fmt.Println(formatRawValue(v))
	}

	return nil
}

func formatRawValue(val interface{}) string {
	if val == nil {
		return ""
	}

	v := reflect.ValueOf(val)
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Slice, reflect.Array:
		// Output slice elements space-separated
		parts := make([]string, v.Len())
		for i := 0; i < v.Len(); i++ {
			parts[i] = formatRawValue(v.Index(i).Interface())
		}
		return strings.Join(parts, " ")
	case reflect.Map:
		// For maps in raw mode, output JSON-like format on single line
		iter := v.MapRange()
		parts := make([]string, 0)
		for iter.Next() {
			key := iter.Key().Interface()
			val := iter.Value().Interface()
			parts = append(parts, fmt.Sprintf("%v=%v", key, formatRawValue(val)))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("%v", val)
	}
}
