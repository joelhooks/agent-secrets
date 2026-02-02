// Package adapters provides interfaces for syncing secrets from external sources.
package adapters

// SourceAdapter defines the interface for pulling secrets from external sources.
type SourceAdapter interface {
	// Pull retrieves secrets from the external source.
	// project: the project identifier (e.g., project name or ID)
	// scope: the environment scope (e.g., "production", "development", "preview")
	// Returns a map of key-value pairs representing the secrets.
	Pull(project, scope string) (map[string]string, error)

	// Name returns the human-readable name of the adapter.
	Name() string
}
