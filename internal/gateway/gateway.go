// Package gateway turns a Gateway (global Oathkeeper handler settings) into the
// handler sections of the Oathkeeper config: checked against Oathkeeper's own
// v25.4.0 config schema, merged into the chart's base config, hashed.
package gateway

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"sigs.k8s.io/yaml"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

// SchemaVersion is the Oathkeeper version the vendored schema comes from.
const SchemaVersion = "v25.4.0"

//go:embed schema/oathkeeper-v25.4.0.config.schema.json
var configSchema []byte

// Kinds are the Oathkeeper config sections a Gateway owns, in config order.
var Kinds = []string{authv1.KindAuthenticators, authv1.KindAuthorizers, authv1.KindMutators, authv1.KindErrors}

// secretKeys may not appear in a Gateway (jinbe writes it; the Oathkeeper
// config ConfigMap is readable): secrets stay in the chart, as env from a Secret.
var secretKeys = []string{"client_secret", "password", "secret", "token"}

var printer = message.NewPrinter(language.English)

var (
	compileOnce sync.Once
	handlers    *jsonschema.Schema
	compileErr  error
)

// handlerSchema is Oathkeeper's config schema reduced to the four handler
// sections (serve/log/tracing reference schemas that are not vendored).
func handlerSchema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		var full map[string]any
		if compileErr = json.Unmarshal(configSchema, &full); compileErr != nil {
			return
		}
		props := full["properties"].(map[string]any)
		sub := map[string]any{
			"$schema":              full["$schema"],
			"definitions":          full["definitions"],
			"type":                 "object",
			"additionalProperties": false,
			"properties":           map[string]any{},
		}
		for _, k := range Kinds {
			sub["properties"].(map[string]any)[k] = props[k]
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if compileErr = c.AddResource("oathkeeper-handlers.json", sub); compileErr != nil {
			return
		}
		handlers, compileErr = c.Compile("oathkeeper-handlers.json")
	})
	return handlers, compileErr
}

// Sections renders the four handler sections: every known handler is listed,
// enabled or not, so the Gateway fully decides them whatever the base says.
func Sections(spec *authv1.GatewaySpec) (map[string]any, error) {
	out := map[string]any{}
	for _, kind := range Kinds {
		sec := map[string]any{}
		set := spec.Handlers(kind)
		for _, name := range authv1.GatewayHandlers[kind] {
			h := map[string]any{"enabled": false}
			if s, ok := set[name]; ok {
				h["enabled"] = s.Enabled
				if s.Config != nil && len(s.Config.Raw) > 0 {
					var cfg any
					if err := json.Unmarshal(s.Config.Raw, &cfg); err != nil {
						return nil, fmt.Errorf("%s.%s.config: %w", kind, name, err)
					}
					h["config"] = cfg
				}
			}
			sec[name] = h
		}
		if kind == authv1.KindErrors {
			fallback := spec.Errors.Fallback
			if len(fallback) == 0 {
				fallback = []string{"json"}
			}
			out[kind] = map[string]any{"handlers": sec, "fallback": fallback}
			continue
		}
		out[kind] = sec
	}
	return out, nil
}

// Validate returns every problem with the spec: Oathkeeper schema violations
// (e.g. an enabled cookie_session without check_session_url), a fallback error
// handler that is not enabled, secrets in a config. Empty means valid.
func Validate(spec *authv1.GatewaySpec) []string {
	var problems []string
	for _, kind := range Kinds {
		for name := range spec.Handlers(kind) {
			if !slices.Contains(authv1.GatewayHandlers[kind], name) {
				problems = append(problems, fmt.Sprintf("%s.%s: unknown handler", kind, name))
			}
		}
	}
	enabledErrors := Enabled(spec).Errors
	fallback := spec.Errors.Fallback
	if len(fallback) == 0 {
		fallback = []string{"json"} // Oathkeeper's default
	}
	for _, f := range fallback {
		if !slices.Contains(enabledErrors, f) {
			problems = append(problems, fmt.Sprintf("errors.fallback: %s is not an enabled error handler", f))
		}
	}
	sections, err := Sections(spec)
	if err != nil {
		return append(problems, err.Error())
	}
	for _, kind := range Kinds {
		for name, s := range spec.Handlers(kind) {
			if s.Config == nil {
				continue
			}
			var cfg any
			_ = json.Unmarshal(s.Config.Raw, &cfg)
			if k := findKey(cfg, secretKeys); k != "" {
				problems = append(problems, fmt.Sprintf("%s.%s.config: %q looks like a secret; keep secrets in the chart (env from a Secret)", kind, name, k))
			}
			if v := findValue(cfg, "vault:"); v != "" {
				problems = append(problems, fmt.Sprintf("%s.%s.config: %q: secret references are not resolved; keep secrets in the chart (env from a Secret)", kind, name, v))
			}
		}
	}
	sch, err := handlerSchema()
	if err != nil {
		return append(problems, "schema: "+err.Error())
	}
	doc, _ := json.Marshal(sections)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return append(problems, err.Error())
	}
	if err := sch.Validate(inst); err != nil {
		var ve *jsonschema.ValidationError
		if ok := asValidation(err, &ve); ok {
			problems = append(problems, leaves(ve)...)
		} else {
			problems = append(problems, err.Error())
		}
	}
	sort.Strings(problems)
	return problems
}

func asValidation(err error, ve **jsonschema.ValidationError) bool {
	v, ok := err.(*jsonschema.ValidationError)
	*ve = v
	return ok
}

// leaves flattens a validation error to "<path>: <message>" lines, keeping the
// most specific causes (oneOf branches report the enabled one).
func leaves(ve *jsonschema.ValidationError) []string {
	if len(ve.Causes) == 0 {
		path := strings.Join(ve.InstanceLocation, ".")
		msg := ve.ErrorKind.LocalizedString(printer)
		// the "enabled: false" branch of each oneOf only says enabled must be false
		if strings.HasSuffix(path, ".enabled") && strings.Contains(msg, "false") {
			return nil
		}
		return []string{path + ": " + msg}
	}
	var out []string
	for _, c := range ve.Causes {
		out = append(out, leaves(c)...)
	}
	return slices.Compact(out)
}

func findKey(v any, keys []string) string {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			if slices.Contains(keys, strings.ToLower(k)) {
				return k
			}
			if f := findKey(sub, keys); f != "" {
				return f
			}
		}
	case []any:
		for _, sub := range t {
			if f := findKey(sub, keys); f != "" {
				return f
			}
		}
	}
	return ""
}

// findValue returns the first string leaf starting with prefix.
func findValue(v any, prefix string) string {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, prefix) {
			return t
		}
	case map[string]any:
		for _, sub := range t {
			if f := findValue(sub, prefix); f != "" {
				return f
			}
		}
	case []any:
		for _, sub := range t {
			if f := findValue(sub, prefix); f != "" {
				return f
			}
		}
	}
	return ""
}

// Render merges the handler sections into the base Oathkeeper config (YAML)
// and returns the full config and its hash. Every other key of the base
// (serve, log, access_rules, tracing, ...) is kept as is.
func Render(base []byte, spec *authv1.GatewaySpec) ([]byte, string, error) {
	cfg := map[string]any{}
	if len(bytes.TrimSpace(base)) > 0 {
		if err := yaml.Unmarshal(base, &cfg); err != nil {
			return nil, "", fmt.Errorf("base config: %w", err)
		}
	}
	sections, err := Sections(spec)
	if err != nil {
		return nil, "", err
	}
	for k, v := range sections {
		cfg[k] = v
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, "", err
	}
	return out, Hash(out), nil
}

// Hash is the first 4 bytes (8 hex chars) of the sha256 of a rendered config;
// it names the versioned config ConfigMap.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// Enabled is the set of handlers the spec enables, sorted.
func Enabled(spec *authv1.GatewaySpec) authv1.GatewayEnabled {
	list := func(m map[string]authv1.GatewayHandler) []string {
		var out []string
		for n, h := range m {
			if h.Enabled {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	return authv1.GatewayEnabled{
		Authenticators: list(spec.Authenticators),
		Authorizers:    list(spec.Authorizers),
		Mutators:       list(spec.Mutators),
		Errors:         list(spec.Errors.Handlers),
	}
}

// InUse lists, per handler, who references it among the live Rules (retired
// Rules match nothing and are skipped): the owning Site, or rule/<name>.
func InUse(rules []okv1.Rule) []authv1.HandlerUse {
	users := map[string][]string{}
	add := func(kind, handler string, r *okv1.Rule) {
		who := "rule/" + r.Name
		if s := r.Labels[render.SiteLabel]; s != "" {
			who = s
		}
		key := kind + "/" + handler
		if !slices.Contains(users[key], who) {
			users[key] = append(users[key], who)
		}
	}
	for i := range rules {
		r := &rules[i]
		if render.Retired(r) || !r.DeletionTimestamp.IsZero() {
			continue
		}
		o := render.ToOathkeeper(r)
		for _, h := range o.Authenticators {
			add(authv1.KindAuthenticators, h.Handler, r)
		}
		add(authv1.KindAuthorizers, o.Authorizer.Handler, r)
		for _, h := range o.Mutators {
			add(authv1.KindMutators, h.Handler, r)
		}
		for _, h := range o.Errors {
			add(authv1.KindErrors, h.Handler, r)
		}
	}
	out := make([]authv1.HandlerUse, 0, len(users))
	for k, u := range users {
		sort.Strings(u)
		out = append(out, authv1.HandlerUse{Handler: k, UsedBy: u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handler < out[j].Handler })
	return out
}

// Disabled returns the in-use handlers the spec does not enable, as
// "<kind>/<name> (used by a, b)".
func Disabled(spec *authv1.GatewaySpec, inUse []authv1.HandlerUse) []string {
	var out []string
	for _, u := range inUse {
		kind, name, _ := strings.Cut(u.Handler, "/")
		if h, ok := spec.Handlers(kind)[name]; !ok || !h.Enabled {
			out = append(out, fmt.Sprintf("%s (used by %s)", u.Handler, strings.Join(u.UsedBy, ", ")))
		}
	}
	return out
}
