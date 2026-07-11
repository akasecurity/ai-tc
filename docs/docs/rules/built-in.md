# Built-in Rules

AKA ships seven rule packs out of the box — **101 detection rules** in total. Every pack is bundled into the plugin and installed active by default, under the log-only **Monitor** policy until you assign a stronger action (Warn / Redact / Block) to a detection from the dashboard. All rules include positive and negative fixtures that run as part of the test suite.

**Pack updates are manual.** The plugin scans with your _installed_ snapshot of each pack (enabled packs only). Upgrading the plugin/CLI records the newer packs as _available_ but changes nothing until you apply the update — from the dashboard's Detections page (**Update**), with `aka detections update`, or after reviewing `/aka:detections` in Claude Code. New packs added in a release are auto-installed (monitor-only); packs you already have are never modified automatically, and your enabled/policy choices survive every update.

**Mixed plugin versions are safe.** Claude Code keeps older plugin versions cached, and a session keeps running the plugin generation it started with — so after an update, still-open sessions execute _old_ hook code. The store defends itself: a database-level write gate silently ignores any in-place rewrite of an installed pack's content outside the manual update flow — and an in-place rewrite is the only write path any shipped binary has ever had for a pack you already have — so an old session's automatic pack recording can neither modify nor revert your installed packs. It also can't record what the newer binary ships — **restart sessions started before a plugin update** to pick up the new plugin (new packs still auto-install from any generation).

## core-pii

**Location:** `rules/core-pii/`

Detects personally identifiable information commonly found in prompts. 14 rules.

| Rule ID              | Severity | Matcher | Description                                               |
| -------------------- | -------- | ------- | --------------------------------------------------------- |
| `email`              | medium   | regex   | Standard email addresses (`user@example.com`)             |
| `ssn`                | high     | regex   | US Social Security Numbers (`123-45-6789`)                |
| `phone-us`           | high     | regex   | US phone numbers incl. +1 and area codes                  |
| `phone-intl`         | high     | regex   | International E.164 numbers                               |
| `ip-address`         | low      | regex   | IPv4 addresses                                            |
| `dob`                | high     | regex   | Dates of birth (1900–2019)                                |
| `drivers-license-us` | high     | regex   | US driver's license numbers (requires license/DL context) |
| `passport-us`        | high     | regex   | US passport numbers (`A12345678`)                         |
| `home-address`       | medium   | keyword | Contextual address phrases                                |
| `name`               | medium   | keyword | Contextual name introduction phrases                      |
| `vin`                | medium   | regex   | Vehicle Identification Numbers (17 chars)                 |
| `mac-address`        | low      | regex   | MAC addresses (`AA:BB:CC:DD:EE:FF`)                       |
| `national-id`        | high     | regex   | Multi-country: Aadhaar, UK NI, Canadian SIN               |
| `zip`                | low      | regex   | US ZIP / ZIP+4 postal codes                               |

## core-financial

**Location:** `rules/core-financial/`

Detects financial account information. 8 rules.

| Rule ID          | Severity | Matcher | Post-Validators | Description                                                         |
| ---------------- | -------- | ------- | --------------- | ------------------------------------------------------------------- |
| `credit-card`    | critical | regex   | `luhn`          | Visa, MC, Amex, Discover card numbers                               |
| `iban`           | high     | regex   | —               | International Bank Account Numbers                                  |
| `routing-number` | high     | regex   | —               | US ABA routing numbers (9 digits, requires routing/ABA/RTN context) |
| `swift`          | high     | regex   | —               | SWIFT/BIC codes (8 or 11 chars, requires SWIFT/BIC context)         |
| `cvv`            | high     | regex   | —               | Card security codes (contextual)                                    |
| `cusip`          | medium   | regex   | —               | US securities identifiers (requires CUSIP context)                  |
| `paypal`         | medium   | regex   | —               | PayPal transaction IDs (requires PayPal context)                    |
| `salary`         | low      | keyword | —               | Salary/compensation contextual phrases                              |

## secrets

**Location:** `rules/secrets/`

Detects credentials and tokens that should never be shared with AI models. 21 rules.

| Rule ID                   | Severity | Matcher | Post-Validators | Description                                                       |
| ------------------------- | -------- | ------- | --------------- | ----------------------------------------------------------------- |
| `aws-access-key`          | critical | regex   | `entropy`       | AWS Access Key IDs (AKIA/ASIA/AROA/etc.)                          |
| `aws-secret-key`          | critical | regex   | `entropy`       | AWS Secret Access Keys (40-char, requires aws-secret-key context) |
| `gcp-service-account`     | critical | regex   | —               | GCP service account emails                                        |
| `azure-connection-string` | critical | regex   | —               | Azure Storage/Service Bus/Cosmos connection strings (two keys)    |
| `openai-api-key`          | critical | regex   | `entropy`       | OpenAI API keys (`sk-proj-...`, `sk-...`)                         |
| `anthropic-api-key`       | critical | regex   | `entropy`       | Anthropic API keys (`sk-ant-...`)                                 |
| `stripe-live-key`         | critical | regex   | `entropy`       | Stripe live keys (`sk_live_`, `pk_live_`)                         |
| `slack-token`             | critical | regex   | —               | Slack tokens (`xoxb-`, `xoxp-`, `xapp-`)                          |
| `discord-token`           | critical | regex   | `entropy`       | Discord bot tokens (3-part format)                                |
| `sendgrid-key`            | critical | regex   | `entropy`       | SendGrid API keys (`SG.`)                                         |
| `twilio-key`              | critical | regex   | —               | Twilio Account SIDs (`AC...`)                                     |
| `gitlab-token`            | critical | regex   | `entropy`       | GitLab PATs (`glpat-`)                                            |
| `digitalocean-token`      | critical | regex   | —               | DigitalOcean PATs (`dop_v1_`)                                     |
| `datadog-key`             | critical | regex   | `entropy`       | Datadog API/APP keys                                              |
| `npm-token`               | critical | regex   | `entropy`       | npm access tokens (`npm_`)                                        |
| `heroku-api-key`          | critical | regex   | —               | Heroku API keys (UUID, requires heroku context)                   |
| `cloudflare-api-key`      | critical | regex   | `entropy`       | Cloudflare API tokens (40-char, requires cloudflare context)      |
| `pulumi-access-token`     | critical | regex   | `entropy`       | Pulumi access tokens (`pul-`)                                     |
| `terraform-cloud-token`   | critical | regex   | `entropy`       | Terraform Cloud user tokens                                       |
| `vault-token`             | critical | regex   | `entropy`       | HashiCorp Vault tokens (`hvs.`, `s.`)                             |
| `github-pat`              | critical | regex   | —               | GitHub PATs/OAuth/App tokens                                      |

## secrets-infra

**Location:** `rules/secrets-infra/`

Detects infrastructure-level secrets and credentials. 13 rules.

| Rule ID                       | Severity | Matcher | Post-Validators | Description                                              |
| ----------------------------- | -------- | ------- | --------------- | -------------------------------------------------------- |
| `ssh-private-key`             | critical | regex   | —               | RSA/DSA/EC/OpenSSH private key blocks                    |
| `db-connection-string`        | critical | regex   | —               | DB URLs with credentials (`postgresql://user:pass@...`)  |
| `jwt-token`                   | high     | regex   | `entropy`       | JSON Web Tokens (3-part base64url)                       |
| `basic-auth-url`              | critical | regex   | —               | HTTP URLs with embedded credentials                      |
| `basic-auth-header`           | critical | regex   | —               | HTTP Basic auth Authorization headers                    |
| `pgp-private-key`             | critical | regex   | —               | PGP private key blocks                                   |
| `bearer-token`                | high     | regex   | `entropy`       | Generic Authorization Bearer tokens                      |
| `env-key-value`               | high     | keyword | —               | Sensitive env vars with values                           |
| `password-field`              | high     | keyword | —               | JSON/YAML password/secret/token fields                   |
| `docker-config-auth`          | critical | regex   | —               | Docker `config.json` base64 auth                         |
| `kubeconfig-token`            | critical | regex   | —               | Kubernetes kubeconfig embedded tokens                    |
| `api-key-header`              | high     | regex   | `entropy`       | API keys in `x-api-key`/`api-key`/`apikey` headers       |
| `generic-high-entropy-secret` | high     | regex   | `entropy`       | High-entropy values on credential-shaped keys (fallback) |

## core-phi

**Location:** `rules/core-phi/`

Detects protected health information (HIPAA-relevant). 8 rules.

| Rule ID            | Severity | Matcher | Description                                                |
| ------------------ | -------- | ------- | ---------------------------------------------------------- |
| `mrn`              | high     | regex   | Medical Record Numbers (contextual)                        |
| `hipaa-identifier` | high     | regex   | Health plan beneficiary / claim numbers                    |
| `member-id`        | high     | regex   | Health plan member IDs                                     |
| `group-id`         | high     | regex   | Health plan group IDs                                      |
| `icd10-code`       | medium   | regex   | ICD-10 diagnosis codes (requires ICD/diagnosis/dx context) |
| `ndc-code`         | medium   | regex   | National Drug Codes                                        |
| `genetic-data`     | high     | keyword | DNA/genetic data references                                |
| `biometric-ref`    | high     | keyword | Biometric data references                                  |

## core-code-context

**Location:** `rules/core-code-context/`

Detects internal code and infrastructure context that should not leave the organization. 8 rules.

| Rule ID           | Severity | Matcher | Description                                                                                            |
| ----------------- | -------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `internal-ip`     | low      | regex   | RFC 1918 private IPs (10.x, 172.16-31.x, 192.168.x)                                                    |
| `localhost-ref`   | low      | regex   | localhost, 127.0.0.1, ::1 references                                                                   |
| `internal-domain` | low      | regex   | `.internal`, `.corp`, `.local` domains                                                                 |
| `file-path`       | low      | regex   | User-home paths (`/home`, `/Users`, `/root`, `C:\Users`) that leak a username / private project layout |
| `stack-trace`     | low      | regex   | Stack traces revealing internal structure                                                              |
| `internal-url`    | low      | keyword | Dev/staging environment URLs                                                                           |
| `feature-flag`    | low      | keyword | Feature flag / toggle names                                                                            |
| `db-table-name`   | low      | keyword | Internal SQL table names                                                                               |

## code-flaws

**Location:** `rules/code-flaws/`

Detects insecure code patterns across Python, JS/TS, Java, Ruby, PHP, and .NET. Rules fire on both code written by Claude (PreToolUse on `Write`/`Edit`) and existing code read from disk (PostToolUse on `Read`). 29 rules covering OWASP Top 10 and related weaknesses.

| Rule ID                     | Severity | Matcher | Description                                                                                     |
| --------------------------- | -------- | ------- | ----------------------------------------------------------------------------------------------- |
| `sql-inject-concat`         | high     | regex   | SQL queries built with `+` string concatenation                                                 |
| `sql-inject-concat-dot`     | high     | regex   | SQL queries built with PHP `.` string concatenation (PHP files only)                            |
| `sql-inject-format`         | high     | regex   | SQL queries via Python `%` format or f-strings                                                  |
| `sql-inject-interp`         | high     | regex   | SQL queries via Ruby `#{}` or PHP `$var` interpolation                                          |
| `cmd-inject-shell`          | critical | regex   | `subprocess.*shell=True` near user-controlled input                                             |
| `cmd-inject-exec`           | critical | regex   | Java `Runtime.getRuntime().exec()` near user input                                              |
| `cmd-inject-node-exec`      | critical | regex   | Node.js `exec`/`execSync` with non-literal argument near user input                             |
| `xss-inner-html`            | high     | keyword | `.innerHTML =` / `.innerHTML=` assignments                                                      |
| `xss-dangerously-set`       | high     | keyword | React `dangerouslySetInnerHTML`                                                                 |
| `xss-unescaped-render`      | high     | regex   | `raw()`, `.html_safe`, `\| safe`, `mark_safe()` in templates                                    |
| `deser-pickle`              | critical | regex   | Python `pickle.loads()` / `pickle.load()`                                                       |
| `deser-yaml-unsafe`         | high     | regex   | `yaml.load()` without `SafeLoader`                                                              |
| `deser-java-ois`            | critical | regex   | Java `ObjectInputStream` + `readObject()`                                                       |
| `hardcoded-password`        | high     | regex   | `password`/`passwd`/`pwd` assigned a high-entropy string literal                                |
| `hardcoded-secret-key`      | high     | regex   | `secret_key`/`api_key`/`auth_token` assigned a high-entropy string literal                      |
| `dev-debug-enabled`         | medium   | regex   | `DEBUG = True` / `debug: true` in config                                                        |
| `dev-placeholder-secret`    | high     | keyword | Placeholder strings (`changeme`, `your-secret`, etc.) near key/token fields                     |
| `dev-wildcard-cors`         | medium   | regex   | CORS wildcard: `Access-Control-Allow-Origin: *`, `origin: '*'`, `CORS_ALLOW_ALL_ORIGINS = True` |
| `auth-ssl-verify-false`     | high     | regex   | `requests.*verify=False` disabling TLS validation                                               |
| `auth-jwt-no-verify`        | critical | regex   | JWT decoded with `verify=False` / `algorithms=[]` near jwt/decode/token                         |
| `path-traversal-open`       | high     | regex   | `open(request.*` / `open(params.*` with user-controlled path                                    |
| `path-traversal-join`       | high     | regex   | `os.path.join(base, user_*)` with user-controlled component                                     |
| `crypto-weak-hash-md5`      | medium   | regex   | MD5 used as a hash (`hashlib.md5`, `MessageDigest("MD5")`, `Digest::MD5`)                       |
| `crypto-weak-hash-sha1`     | medium   | regex   | SHA-1 used near password/credential/token context                                               |
| `crypto-insecure-random`    | medium   | regex   | `Math.random()` / `random.random()` near security-sensitive labels                              |
| `prototype-pollution-merge` | high     | regex   | `Object.assign(target, req.body)` / `_.merge(target, request.*)`                                |
| `eval-dynamic-exec`         | critical | regex   | `eval`/`exec` with non-literal argument near user input                                         |
| `ssrf-user-url`             | high     | regex   | `fetch`/`axios`/`requests.get` called directly with `req.*`/`params.*`                          |
| `regex-redos-backtrack`     | medium   | regex   | Catastrophic backtracking patterns like `(a+)+`                                                 |

## config-posture

Structural rules over the plugin's [configuration-inventory scan](../plugin/claude-code.md#configuration-inventory-scan-skills-hooks-mcp-servers-config-files) (skills & hooks), evaluated once per session on `SessionStart`. Unlike the text packs above, these compare hook entries against each other, so they live as pure functions in `packages/detections/src/posture/` (fixture-tested like every pack) rather than in the regex rule format. Findings are observational (`warn`) and power the hook status/warning lines on the config read surface.

| Rule                   | Severity | Fires when                                                                                                     |
| ---------------------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| `hook-conflict`        | medium   | Two hooks on the same event with overlapping matchers both mutate the tool target — run order is undefined     |
| `hook-unknown`         | medium   | A settings-scope hook's command is attributable to no installed plugin and no recognizable tool (v1 heuristic) |
| `hook-external-egress` | high     | A hook command contains network-egress primitives (`curl`, `wget`, `nc`, `ssh`, …) or a URL                    |

## Running the test suite

```bash
pnpm --filter @akasecurity/detections test

# Watch mode during rule development
pnpm --filter @akasecurity/detections test -- --watch
```

Fixture tests auto-discover across all packs - no need to register new rules manually.

## Adding your own rules

See [Writing Rules](writing-rules.md) for the full guide. Create a new directory under `rules/`, add a `manifest.json`, your rule JSON files, and `fixtures/` — the test runner and pack loader auto-discover everything.
