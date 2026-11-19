package main

import (
	"strings"
	"testing"
)

func TestReadPipedSecretKeepsEveryLine(t *testing.T) {
	// Shaped like a PEM block (header, body lines, footer) without key markers.
	pem := "first line\nAAAA\nBBBB\nlast line\n"
	got, err := readPipedSecret(strings.NewReader(pem))
	if err != nil {
		t.Fatalf("readPipedSecret: %v", err)
	}
	if got != pem {
		t.Fatalf("got %q, want %q", got, pem)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(pem) {
		t.Fatalf("trimmed value lost lines")
	}
}

func TestReadPipedSecretSingleLineUnchanged(t *testing.T) {
	got, err := readPipedSecret(strings.NewReader("token-value\n"))
	if err != nil {
		t.Fatalf("readPipedSecret: %v", err)
	}
	if strings.TrimSpace(got) != "token-value" {
		t.Fatalf("got %q", got)
	}
}

func TestReadPipedSecretRefusesOversize(t *testing.T) {
	big := strings.Repeat("x", maxPipedSecretBytes+1)
	if _, err := readPipedSecret(strings.NewReader(big)); err == nil {
		t.Fatalf("expected an error for a value over %d bytes", maxPipedSecretBytes)
	}
}

func TestReadPipedSecretAtLimit(t *testing.T) {
	exact := strings.Repeat("x", maxPipedSecretBytes)
	got, err := readPipedSecret(strings.NewReader(exact))
	if err != nil {
		t.Fatalf("readPipedSecret at limit: %v", err)
	}
	if len(got) != maxPipedSecretBytes {
		t.Fatalf("len %d", len(got))
	}
}
