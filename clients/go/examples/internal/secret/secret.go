// Package secret reads key material for the example programs without requiring
// it on the command line.
//
// A flag value is visible in `ps auxww` and in /proc/<pid>/cmdline — which is
// world-readable on a default Linux install — and it lands in shell history and
// in any shell-tracing or process-accounting log. For a BIP 352 scan or spend
// secret that is a disclosure of funds, not merely of configuration.
//
// So the silent-payment examples take their secrets from the environment and
// accept a flag only with a warning on stderr. The point is not that an example
// needs hardening; it is that these two files are the ones a wallet integrator
// copies hardest, and a pattern copied from here should not carry the exposure
// with it.
package secret

import (
	"fmt"
	"os"
)

// FromEnvOrFlag returns the secret in envVar if it is set, else flagValue with a
// warning, else an error naming both ways to supply it.
func FromEnvOrFlag(envVar, flagValue, flagName string) (string, error) {
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}
	if flagValue != "" {
		fmt.Fprintf(os.Stderr,
			"warning: %s puts a secret in `ps` output, /proc/<pid>/cmdline, and shell history; set %s instead\n",
			flagName, envVar)
		return flagValue, nil
	}
	return "", fmt.Errorf("no secret supplied: set %s (preferred) or pass %s", envVar, flagName)
}
