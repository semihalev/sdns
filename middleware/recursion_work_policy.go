package middleware

import (
	"fmt"

	"github.com/semihalev/sdns/config"
)

// MustRecursionWorkPolicyFromConfig normalizes, validates, and translates the
// operator-facing recursion-firewall configuration. Resolver and pipeline
// construction both use this seam so programmatic callers cannot silently
// turn an unknown mode into a different security policy.
func MustRecursionWorkPolicyFromConfig(raw config.RecursionFirewallConfig) RecursionWorkPolicy {
	raw.Normalize()
	if err := raw.Validate(); err != nil {
		panic(fmt.Sprintf("invalid recursion firewall config: %v", err))
	}

	mode := RecursionWorkShadow
	switch raw.Mode {
	case config.RecursionFirewallModeOff:
		mode = RecursionWorkOff
	case config.RecursionFirewallModeShadow:
		mode = RecursionWorkShadow
	case config.RecursionFirewallModeEnforce:
		mode = RecursionWorkEnforce
	}

	return RecursionWorkPolicy{
		Mode:               mode,
		MaxOutboundQueries: raw.MaxOutboundQueries,
		MaxInternalQueries: raw.MaxInternalQueries,
	}
}
