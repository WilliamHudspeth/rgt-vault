package servecmd

import (
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/actions"
)

// RGT-523: --destinations=enforce|warn (env RGT_VAULT_DESTINATIONS),
// default enforce; anything else is refused.
func TestDestinationsFlag(t *testing.T) {
	home := map[string]string{"HOME": t.TempDir()}
	if cfg, err := parse(flagsOf(nil), env(home)); err != nil || cfg.destinations != actions.DestinationsEnforce {
		t.Fatalf("default: %v %v", cfg.destinations, err)
	}
	if cfg, err := parse(flagsOf(func(f *Flags) { f.Destinations = "warn" }), env(home)); err != nil || cfg.destinations != actions.DestinationsWarn {
		t.Fatalf("flag: %v %v", cfg.destinations, err)
	}
	e := map[string]string{"HOME": home["HOME"], "RGT_VAULT_DESTINATIONS": "warn"}
	if cfg, err := parse(flagsOf(nil), env(e)); err != nil || cfg.destinations != actions.DestinationsWarn {
		t.Fatalf("env: %v %v", cfg.destinations, err)
	}
	if _, err := parse(flagsOf(func(f *Flags) { f.Destinations = "off" }), env(home)); err == nil {
		t.Fatal("--destinations=off accepted")
	}
	if f := NewCommand(Env{}, nil).Flags().Lookup("destinations"); f == nil || f.DefValue != "enforce" {
		t.Fatalf("flag = %+v", f)
	}
}
