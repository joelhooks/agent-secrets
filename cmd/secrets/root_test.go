package main

import "testing"

func TestRootCommandDoesNotExposeLegacyOutputFlags(t *testing.T) {
	if rootCmd.PersistentFlags().Lookup("human") != nil {
		t.Fatalf("expected --human flag to be removed")
	}

	if rootCmd.PersistentFlags().Lookup("output") != nil {
		t.Fatalf("expected --output flag to be removed")
	}
}
