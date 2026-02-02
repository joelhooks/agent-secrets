package scanner

import "regexp"

// Severity represents the severity level of a detected secret.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Pattern represents a secret detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    Severity
	Description string
}

// DefaultPatterns returns the default set of secret detection patterns.
func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "GitHub Personal Access Token",
			Regex:       regexp.MustCompile(`ghp_[a-zA-Z0-9]{32,}`),
			Severity:    SeverityCritical,
			Description: "GitHub personal access token",
		},
		{
			Name:        "GitHub OAuth Token",
			Regex:       regexp.MustCompile(`gho_[a-zA-Z0-9]{32,}`),
			Severity:    SeverityCritical,
			Description: "GitHub OAuth access token",
		},
		{
			Name:        "GitHub User-to-Server Token",
			Regex:       regexp.MustCompile(`ghu_[a-zA-Z0-9]{32,}`),
			Severity:    SeverityCritical,
			Description: "GitHub user-to-server token",
		},
		{
			Name:        "GitHub Server-to-Server Token",
			Regex:       regexp.MustCompile(`ghs_[a-zA-Z0-9]{32,}`),
			Severity:    SeverityCritical,
			Description: "GitHub server-to-server token",
		},
		{
			Name:        "GitHub Refresh Token",
			Regex:       regexp.MustCompile(`ghr_[a-zA-Z0-9]{32,}`),
			Severity:    SeverityCritical,
			Description: "GitHub refresh token",
		},
		{
			Name:        "AWS Access Key ID",
			Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Severity:    SeverityCritical,
			Description: "AWS access key ID",
		},
		{
			Name:        "AWS Secret Access Key",
			Regex:       regexp.MustCompile(`aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
			Severity:    SeverityCritical,
			Description: "AWS secret access key",
		},
		{
			Name:        "Stripe Live Secret Key",
			Regex:       regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),
			Severity:    SeverityCritical,
			Description: "Stripe live secret key",
		},
		{
			Name:        "Stripe Test Secret Key",
			Regex:       regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`),
			Severity:    SeverityMedium,
			Description: "Stripe test secret key",
		},
		{
			Name:        "Stripe Live Publishable Key",
			Regex:       regexp.MustCompile(`pk_live_[a-zA-Z0-9]{24,}`),
			Severity:    SeverityHigh,
			Description: "Stripe live publishable key",
		},
		{
			Name:        "Stripe Test Publishable Key",
			Regex:       regexp.MustCompile(`pk_test_[a-zA-Z0-9]{24,}`),
			Severity:    SeverityLow,
			Description: "Stripe test publishable key",
		},
		{
			Name:        "Generic API Key",
			Regex:       regexp.MustCompile(`(?i)api[_-]?key['\"]?\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?`),
			Severity:    SeverityMedium,
			Description: "Generic API key pattern",
		},
		{
			Name:        "Generic Secret",
			Regex:       regexp.MustCompile(`(?i)secret['\"]?\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?`),
			Severity:    SeverityMedium,
			Description: "Generic secret pattern",
		},
		{
			Name:        "Generic Password",
			Regex:       regexp.MustCompile(`(?i)password['\"]?\s*[:=]\s*['"]?[a-zA-Z0-9_\-!@#$%^&*]{8,}['"]?`),
			Severity:    SeverityMedium,
			Description: "Generic password pattern",
		},
		{
			Name:        "Generic Token",
			Regex:       regexp.MustCompile(`(?i)token['\"]?\s*[:=]\s*['"]?[a-zA-Z0-9_\-\.]{20,}['"]?`),
			Severity:    SeverityMedium,
			Description: "Generic token pattern",
		},
		{
			Name:        "Private Key",
			Regex:       regexp.MustCompile(`-----BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE KEY-----`),
			Severity:    SeverityCritical,
			Description: "Private key (RSA, EC, or OpenSSH)",
		},
		{
			Name:        "JSON Web Token",
			Regex:       regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
			Severity:    SeverityHigh,
			Description: "JSON Web Token (JWT)",
		},
	}
}
