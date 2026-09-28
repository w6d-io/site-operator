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

`ingress: per-site` (default `wildcard`) is for a domain other Ingresses in the cluster
already use (e.g. the sandbox on `dev.example.com`): the Zone renders **no** wildcard
Ingress (`IngressReady=True PerSite`); each **host** under it gets one exact-host Ingress
`host-<hash8 of host>` (annotation `auth.w6d.io/host`) from the fixed template (backend
oathkeeper-proxy), shared by every Site on that host (route prefixes, e.g. wallets-api
`/wallets/api` and wallets-treasury `/wallets/treasury`): each Site is a plain owner (none is
the controller), the Ingress goes with the last one (the operator releases a deleted Site's
reference itself, the GC does too), TLS from the Zone
(`default`: no tls block, the controller's default/wildcard certificate; `secret` / `issuer`:
the Zone's Secret, mirrored into `site-operator-zones` key `secrets` for admission).

Before creating a host or vanity Ingress, the operator checks **every** Ingress in the
cluster (read-only cluster-wide watch) except its own (Zone wildcards, `site-*`, `host-*` in
the gateway namespace): if one serves a host
**exactly**, nothing is created and `IngressReady=False HostTaken` names `<namespace>/<name>`;
an Ingress of ours that already serves is kept, not taken down. A **wildcard** one label
above (e.g. `loki/loki-alloy` `*.dev.example.com` `/collect` on dev-aws-1) is not a
collision: nginx gives the host to the exact-host server block, so the Site's Ingress is
created (`IngressReady` stays True) and the warning condition `HostShadowsWildcard=True`
(not part of Ready, plus a Warning event) says `<ns>/<name> serves *.<parent>; nginx routes
<host> to this Site (paths of that Ingress, e.g. /collect, are not served on this host)`. This operator's own
Zone wildcards are ignored. When the other Ingress goes away the Site's Ingress is created (Ingress watch).
Switching a Zone's mode is handled both ways: to `per-site` the wildcard is deleted and the
host Ingresses are created; to `wildcard` the wildcard is created and the host Ingresses
are released (expect a short gap while both controllers reconcile). Admission: a `site-*` Ingress
serves exact hosts one label under a Zone, is controlled by the Site it is named after, and
uses its own `site-<name>-tls` Secret or a Zone's (the policy cannot read the Site, so the
host-to-Site match is the operator's); a `host-*` Ingress serves exactly the one host of its
`auth.w6d.io/host` annotation, is owned only by Sites (no controller) and uses a Zone Secret.

## Gateway (global handlers)

`Gateway` (namespaced singleton `default`, `config/samples/gateway.yaml`) holds the global
Oathkeeper handler settings kuma edits: `authenticators`, `authorizers`, `mutators`
(`{<name>: {enabled, config}}`) and `errors: {handlers, fallback}`, every handler of
Oathkeeper v25.4.0. Handlers left out are disabled. jinbe writes it (no delete); the
operator:

1. checks every handler config against Oathkeeper's own config schema (vendored
   `internal/gateway/schema/oathkeeper-v25.4.0.config.schema.json`), the fallback against the
   enabled error handlers, and refuses secret-looking keys (`client_secret`, `password`, ...:
   secrets stay in chart env from a Secret) → `Validated=False InvalidConfig`;
2. refuses to disable a handler any live Rule uses → `Validated=False HandlerInUse`, with the
   Sites (or `rule/<name>`); `status.inUse` always lists every used handler;
3. merges the four sections into the chart's base config (`--gateway-base-configmap`, key
   `--gateway-config-key`; serve, log, access_rules, tracing untouched) and creates an
   **immutable, versioned** ConfigMap `<--gateway-config-prefix>-<hash8>` (the name is the
   content hash);
4. rolls `--gateway-deployment` by pointing its config volume (`--gateway-config-volume`) at
   that ConfigMap and setting the pod-template annotation `auth.w6d.io/gateway-config-hash`:
   a real rolling update, pods not yet replaced keep mounting the previous config. Admission
   lets the operator change nothing else on the Deployment, and create/delete no ConfigMap
   but versioned ones (created immutable);
5. waits for every replica updated and Ready, then for every pod to serve every acknowledged
   Rule (a handler config Oathkeeper rejects drops the Rules using it) → `Rolled`, `Ready`;
   `status.configMap` / `configHash` / `enabled` then describe what serves;
6. on `--gateway-rollout-timeout` (5 m) or `ProgressDeadlineExceeded`, points the volume back at
   the last good config (`status.configMap`; first time: the chart's seed ConfigMap) →
   `Applied=False RolledBack`, `status.failedHash`; that spec is not retried until it changes;
7. keeps the newest 3 revisions (`status.revisions`) and deletes older ones, never the one in
   use or the last good one; the chart's seed is never deleted.

Site validation (`HandlerNotEnabled`) uses the handlers both live (`status.enabled`) and still
wanted by the spec, so no Site can use a handler before its rollout or while it is being
disabled; without a rolled-out Gateway the `--enabled-*` flags apply. Deleting the Gateway
leaves the config as it is.

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

Oathkeeper answers 500 when two rules match a request, and caches the authorizer
payload and mutator templates by rule id. A Rule name is therefore
`<site>-<gate>-<hash8 of authorizer + mutators>`:

- **same templates** (routes, methods, upstream, authenticators, errors): the Rule keeps
  its name and is updated in place — one maester write, no gap (measured: 0 non-200 in
  30 636 requests across 25 route changes);
- **changed template**: a new Rule, swapped in three steps inside one reconcile:
  1. **retire** each Rule no longer wanted: its `match.url` becomes
     `https://<rule-name>.retired.invalid/` (unique, unroutable) — annotation `auth.w6d.io/retired`;
  2. **create** the new Rules; 3. **delete** the retired Rules.

How maester (sidecar mode, v0.1.14 = `ory/oathkeeper-maester@72046a0`) behaves: one worker
per pod; every reconcile lists **all** Rules from its informer cache and rewrites the whole
file, keeping only Rules with `status.validation.valid == true`. The informer delivers the
three steps in order, so no file holds the new Rule next to a live old one. The cost is a
short **404** (fail-closed) for the changed gate between the write that retires the old Rule
and the write that includes the new one (measured on kind, 2 replicas: 0 × 500 in ~30 000
requests over 25 swaps per run, 404 windows p50 12 ms, p95 28 ms, max 33 ms per pod).

Two upstream maester defects, both seen on kind with 2 replicas (fix:
`hack/maester-sidecar.patch`, to upstream; run a patched image until then):

- the file is written with `os.Create` (truncate, then write): Oathkeeper can read the empty
  file, which decodes as **zero rules** → gateway-wide 404 blips on every Rule change of any
  site (16 × 404 on an untouched site over 40 changes). Patch: temp file + rename (0 in 51 000);
- each replica's sidecar races on the one shared finalizer; the one that loses gets NotFound
  and does not rewrite its file, so **a deleted Rule stays live on that pod** until the next
  Rule event (seen: 1 deleted site still served on 1 of 2 pods). Patch: on NotFound, rewrite
  the file from the cache. Retired Rules lingering this way match nothing.

Envtest `TestTemplateChangeSwapsRuleSafely` replays a Rule watch and asserts two live Rules
for one gate never coexist; `TestRouteChangeUpdatesRuleInPlace` covers in-place updates.

## Status

Gateway conditions: `Validated`, `Applied`, `Rolled`, `Ready` (see Gateway above).

Site conditions: `Validated`, `RulesSynced` (maester acknowledged every Rule),
`RulesLoaded`, `IngressReady` / `CertificateReady` (the Zone's, or the vanity
Ingress/Certificate), `Ready` (all of them).

`RulesLoaded`: the operator lists the Ready pods matching `--gateway-pod-selector` in the
gateway namespace (pods get/list, uncached, no watch) and reads each pod's
`GET :<--gateway-api-port>/rules` (paged, 2 s per pod). True once every pod serves every
rendered rule id with its rendered match URL; the message gives the latency since the rules
were written. While pods lag it rechecks (20 ms for 1 s, then 500 ms, then 2 s) without
blocking; after `--rules-loaded-timeout` (60 s) it reports `Timeout` and rechecks every
30 s. An empty selector disables the probe (`NotChecked`, True).
`Validated=False` or gatekit unavailable writes nothing and leaves the previous Rules serving.
