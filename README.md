# site-operator

Turns `sites.auth.w6d.io` (written by jinbe) into oathkeeper-maester `Rule` CRs, and
admin-defined `zones.auth.w6d.io` into one wildcard `Ingress` (+ `Certificate`) each.
Design: `../docs/SERVICE_PLUG.md`, `../docs/research/site-operator.md`.

- `api/v1alpha1` Site and Zone types · `api/oathkeeper/v1alpha1` the maester Rule fields used
- `internal/render` pure Site/Zone → children (Rule names `<site>-<gate>-<hash8>`)
- `internal/validate` static checks + gatekit `/compile` `/overlap` client (and a mock)
- `internal/controller` Site and Zone reconcilers, status conditions
- `config/` CRDs, RBAC (operator Role + zones ClusterRole, `site-writer` Role for jinbe),
  ValidatingAdmissionPolicies, Deployment
- `test/policy` admission policies + RBAC against a real kube-apiserver (envtest 1.35),
  including every Ingress the auth chart renders (`hack/render-chart-ingresses.sh`)
- `test/gatekit` the gatekit client against the real gatekit binary (built from `../gatekit`,
  or `GATEKIT_URL`); skipped when neither is available

```sh
make test     # vet + envtest (setup-envtest use 1.35.0 first)
make render   # kustomize config/default
```

## Zones

A `Zone` (cluster-scoped, admins only) is a wildcard domain, e.g. `dev.example.com`.
The operator renders one Ingress `zone-<name>` for `*.<domain>` → oathkeeper proxy,
and for `tls.mode: issuer` one wildcard Certificate (DNS-01 issuer). A Site host must be
exactly one DNS label under a Zone domain (a wildcard certificate covers one label); with
`exposure.mode: zone` (default) it needs **rules only**. `exposure.mode: vanity` (opt-in)
adds a per-site Ingress from the fixed template, with `tls: per-site` for its own Certificate. The operator mirrors the Zone domains into ConfigMap `site-operator-zones`
(RBAC: update by name only), which the `site-operator-hosts` admission policy reads.

## Upstreams

Structured `{service, namespace, port, scheme}`, rendered as
`<scheme>://<service>.<namespace>.svc.cluster.local:<port>`. CRD CEL refuses platform
namespaces; operator flags and the admission policy refuse Kratos admin, OPA/OPAL, Redis,
Postgres (names and ports). A `remote_json` authorizer must pin `"app":"<site>"` in its payload.

## gatekit

`POST /compile` then `POST /overlap` (contract: `../gatekit/README.md`). `Validated=False`
when a pattern does not compile, when `/overlap` lists any `invalid` rule (one already breaks
the gateway), or when an overlap pair involves one of this Site's rules. An overlap between
two other sites does not lock every site out. Non-2xx (e.g. 503 over budget) or no answer:
`Validated=Unknown`, nothing written, retry in 30 s.

## Pause

`spec.paused: true` swaps the gate Rules for one deny Rule per host (`<https?>://host/<.*>`,
all methods): 403, browsers redirected to `--paused-redirect-url?site=<name>` when set, JSON
clients get the json error. The vanity Ingress stays. It needs no gatekit call, so a site can
be paused while gatekit is down. Resume swaps the gate Rules back (same order as below).

## Ingress annotations

Allowed on any Ingress in the gateway namespace (policy params): the operator's own set plus
every key the chart renders for dev-aws-1/auth, auth-dev and prod-aws-1/auth —
`cert-manager.io/cluster-issuer`, `nginx.ingress.kubernetes.io/{enable-cors, cors-allow-origin,
cors-allow-credentials, cors-allow-methods, cors-allow-headers, cors-expose-headers,
cors-max-age, custom-http-errors, proxy-read-timeout, proxy-send-timeout, proxy-body-size}`,
`nginx.ingress.kubernetes.io/default-backend` (value pinned to `error-page`), Helm/Argo
bookkeeping prefixes. The chart's `kratos-login-ui` Ingress (disabled in all three envs)
points at the login UI, not the gateway, and would be refused if enabled.

## Rule swaps (no 500 window)

Oathkeeper answers 500 when two rules match a request and caches header templates by rule
id, so a changed gate gets a new Rule name. How maester (sidecar mode) behaves, read from
`ory/oathkeeper-maester@98a7931 controllers/rule_controller.go`:

- one worker; every reconcile lists **all** Rules from its informer cache and rewrites the
  whole rules file, keeping only Rules with `status.validation.valid == true`;
- it only drops a Rule from the file in the reconcile of that Rule's own deletion (it holds
  a finalizer); any other reconcile still writes a Rule that is being deleted if the cache
  has it. With create-then-delete, the file can hold old + new (500), and a stale write
  after the deletion can keep the old Rule there until the next unrelated event.

The operator therefore swaps in three steps inside one reconcile:

1. **retire** each Rule no longer wanted: its `match.url` becomes
   `https://<rule-name>.retired.invalid/` (unique, unroutable) — annotation `auth.w6d.io/retired`;
2. **create** the new Rules;
3. **delete** the retired Rules.

The informer delivers these events in order, so any file maester writes that contains the
new Rule already sees the old one retired (or gone); a stale copy of a retired Rule matches
nothing. The worst case is a short **404** (fail-closed) for the changed gate's URLs,
between the write that retires the old Rule and the write that includes the new one once
maester has marked it valid (two maester reconciles, tens of ms). Envtest
`TestTemplateChangeSwapsRuleSafely` replays a Rule watch and asserts two live Rules for one
gate never coexist. The measurement against the real maester is task OP-4 / MA-1.

## Status

Site conditions: `Validated`, `RulesSynced` (maester acknowledged every Rule),
`RulesLoaded` (Unknown until OP-3's per-pod `:4456/rules` probe), `IngressReady` /
`CertificateReady` (the Zone's, or the vanity Ingress/Certificate), `Ready`.
`Validated=False` or gatekit unavailable writes nothing and leaves the previous Rules serving.
