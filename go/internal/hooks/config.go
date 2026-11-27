package hooks

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"rgt-vault-server/internal/hooks/pyfmt"
)

// Config is the hook configuration (python hook_from_config's dict):
//
//	mode: off | log | webhook | two_factor
//	freeze_file: /path/to/freeze              # optional
//	webhook: {url, timeout_seconds, bearer_token, allow_remote}
//	two_factor: {shared_secret | shared_secret_env, max_ttl_seconds}
type Config struct {
	Mode       string           `json:"mode" yaml:"mode"`
	FreezeFile string           `json:"freeze_file" yaml:"freeze_file"`
	Webhook    *WebhookConfig   `json:"webhook" yaml:"webhook"`
	TwoFactor  *TwoFactorConfig `json:"two_factor" yaml:"two_factor"`
}

// WebhookConfig configures the webhook mode.
type WebhookConfig struct {
	URL string `json:"url" yaml:"url"`
	// TimeoutSeconds; 0 means 5.
	TimeoutSeconds float64 `json:"timeout_seconds" yaml:"timeout_seconds"`
	BearerToken    string  `json:"bearer_token" yaml:"bearer_token"`
	// AllowRemote permits non-loopback webhook hosts (Go-only; see
	// WebhookHook).
	AllowRemote bool `json:"allow_remote" yaml:"allow_remote"`
}

// TwoFactorConfig configures the two_factor mode. SharedSecret wins over
// SharedSecretEnv (the name of an environment variable holding it).
type TwoFactorConfig struct {
	SharedSecret    string `json:"shared_secret" yaml:"shared_secret"`
	SharedSecretEnv string `json:"shared_secret_env" yaml:"shared_secret_env"`
	// MaxTTLSeconds; 0 means 3600.
	MaxTTLSeconds int `json:"max_ttl_seconds" yaml:"max_ttl_seconds"`
}

// maxWebhookTimeoutSeconds bounds timeout_seconds so the conversion to a
// time.Duration cannot overflow.
const maxWebhookTimeoutSeconds = 3600

// FromConfig builds a hook (python hook_from_config). An empty mode is
// "off"; "soar" was removed (use webhook); errors match
// validation.ErrValidation.
func FromConfig(cfg Config) (Hook, error) {
	return fromConfig(cfg, os.Getenv)
}

func fromConfig(cfg Config, getenv func(string) string) (Hook, error) {
	mode := strings.ToLower(cfg.Mode)
	if mode == "" {
		mode = "off"
	}
	var h Hook
	switch mode {
	case "soar":
		return nil, validationErr("hook mode 'soar' has been removed; SOAR products integrate through 'webhook' mode")
	case "off":
		h = NewOffHook()
	case "log":
		h = NewLogHook()
	case "webhook":
		if cfg.Webhook == nil || cfg.Webhook.URL == "" {
			return nil, validationErr("webhook hook requires config['webhook']['url']")
		}
		w := cfg.Webhook
		if w.TimeoutSeconds < 0 || w.TimeoutSeconds > maxWebhookTimeoutSeconds || math.IsNaN(w.TimeoutSeconds) {
			return nil, validationErr("webhook timeout_seconds must be between 0 and 3600")
		}
		wh, err := NewWebhookHook(w.URL,
			WithTimeout(time.Duration(w.TimeoutSeconds*float64(time.Second))),
			WithBearerToken(w.BearerToken),
			WithAllowRemote(w.AllowRemote))
		if err != nil {
			return nil, err
		}
		h = wh
	case "two_factor":
		tf := cfg.TwoFactor
		if tf == nil {
			tf = &TwoFactorConfig{}
		}
		secret := tf.SharedSecret
		if secret == "" && tf.SharedSecretEnv != "" {
			secret = getenv(tf.SharedSecretEnv)
		}
		if secret == "" {
			return nil, validationErr("two_factor hook requires a shared_secret (config or env var).")
		}
		maxTTL := tf.MaxTTLSeconds
		if maxTTL == 0 {
			maxTTL = 3600
		}
		th, err := NewTwoFactorHook([]byte(secret), WithMaxTTL(maxTTL))
		if err != nil {
			return nil, err
		}
		h = th
	default:
		return nil, validationErr(fmt.Sprintf("unknown hook mode %s", pyfmt.Repr(mode)))
	}
	if cfg.FreezeFile != "" {
		h.SetFreezeFile(cfg.FreezeFile)
	}
	return h, nil
}
