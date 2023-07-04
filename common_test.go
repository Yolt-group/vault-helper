package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func errorTestValidate(t *testing.T, expected bool, err error) {
	if expected {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

func printTestCycle(t *testing.T, current, length int) {
	t.Logf("Test %d/%d", current, length)
}
