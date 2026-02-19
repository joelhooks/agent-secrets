package output

// Formatter handles output formatting
type Formatter interface {
	Format(r Response) error
}

// GetFormatter always returns JSON output formatter.
func GetFormatter() Formatter {
	return &JSONFormatter{}
}
