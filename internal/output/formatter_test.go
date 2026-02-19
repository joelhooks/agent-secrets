package output

import (
	"testing"
)

func TestGetFormatterAlwaysReturnsJSONFormatter(t *testing.T) {
	formatter := GetFormatter()
	if formatter == nil {
		t.Fatal("GetFormatter returned nil")
	}

	if _, ok := formatter.(*JSONFormatter); !ok {
		t.Fatalf("expected *JSONFormatter, got %T", formatter)
	}
}
