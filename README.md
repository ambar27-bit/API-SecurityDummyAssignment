# DummyJSON API Security Test Framework

**QA Automation Engineering Assessment**

---

## Contents

1. [Quick Start](#quick-start)
2. [Test Strategy](#test-strategy)
3. [Architecture](#architecture)
4. [Security Matrix](#security-matrix)
5. [Key Findings](#key-findings)
6. [Assumptions and Limitations](#assumptions-and-limitations)
7. [CI Pipeline](#ci-pipeline)
8. [Actual Effort](#actual-effort)
9. [AI-Assisted Development Disclosure](#ai-assisted-development-disclosure)

---

## Quick Start

### Prerequisites

- Node.js 18 or later
- npm 9 or later

### Installation

```bash
# 1. Install dependencies
npm install

# 2. Configure credentials
cp .env.example .env
```

> No browser binaries are needed. This is a pure API test suite — Playwright's APIRequestContext makes HTTP calls directly without launching a browser.

### Configure credentials

The framework resolves credentials from environment variables. Three sources are supported — the first that provides a value wins:

#### Option 1 — `.env` file (local development, recommended for local runs)

```bash
cp .env.example .env
```

Open `.env` and fill in three pairs of DummyJSON credentials. Any valid users from the public dataset work — credentials are visible at **https://dummyjson.com/users** (this is intentional, it is a public sandbox). Pick three users with different IDs. At least one should have `"role": "admin"` for RBAC tests to be meaningful.

```
BASE_URL=https://dummyjson.com

ADMIN_USERNAME=emilys          # role: admin
ADMIN_PASSWORD=emilyspass

USER_USERNAME=michaelw         # role: user (different ID from admin)
USER_PASSWORD=michaelwpass

USER2_USERNAME=sophiab         # role: user (different ID from USER)
USER2_PASSWORD=sophiabpass
```

> `.env` is listed in `.gitignore` and must never be committed. The `.env.example` file shows required keys with no values.

#### Option 2 — CI secret manager (GitHub Actions)

Credentials are injected as environment variables from GitHub Actions repository secrets. Go to: **Settings → Secrets and variables → Actions → New repository secret** and add each key from `.env.example`. The workflow file reads them as `${{ secrets.ADMIN_USERNAME }}` — no credentials ever appear in workflow files or logs.

#### Option 3 — External secret manager (production pipelines)

For AWS Secrets Manager, Azure Key Vault, HashiCorp Vault or similar — resolve secrets at pipeline startup and inject as environment variables before running `npm test`. The framework is secret-manager-agnostic by design: it reads from `process.env` regardless of how values got there.

Example using AWS SSM Parameter Store:

```bash
export ADMIN_USERNAME=$(aws ssm get-parameter \
  --name /dummyjson/admin-username \
  --with-decryption \
  --query Parameter.Value --output text)

export ADMIN_PASSWORD=$(aws ssm get-parameter \
  --name /dummyjson/admin-password \
  --with-decryption \
  --query Parameter.Value --output text)

# repeat for USER_* and USER2_* ...

npm test
```

This pattern keeps the test framework decoupled from any specific cloud provider SDK.

### Run All Tests

```bash
npm test
```

### Run a Specific Suite

```bash
npm run test:auth        # Authentication and token tests
npm run test:rbac        # Role-based authorisation tests
npm run test:ownership   # Resource ownership tests
npm run test:schema      # Schema validation and data exposure
npm run test:negative    # Negative and boundary scenarios
npm run test:matrix      # Data-driven security matrix runner
```

### View the Report

**Live Allure report (published from CI):**
👉 https://ambar27-bit.github.io/API-SecurityDummyAssignment/

The report is regenerated and published to GitHub Pages on every CI run. You can also generate reports locally:

```bash
npm run report          # Playwright HTML report
npm run allure:generate # build the Allure report (requires Java)
npm run allure:open     # view the Allure report
```

Both report on all executed scenarios, timings, and security findings.

---

## Test Strategy

### Problem Analysis

DummyJSON is a public sandbox API that provides dummy user data for prototyping. It exposes:

- Authentication endpoints (`/auth/login`, `/auth/me`, `/auth/refresh`)
- A user directory with ~208 users, each having `admin`, `moderator` or `user` roles
- User-scoped resources: carts, todos, posts
- Products and carts as shared resources

**Critical observation:** DummyJSON does not implement a production security model. Credentials are visible in the user list, there is no RBAC enforcement, and all endpoints (including destructive ones) are accessible without authentication. The assessment framework treats this correctly: it documents the gap between observed behaviour and production security expectations rather than modifying expectations to make the suite green.

### Risk Prioritisation

Risks were prioritised using a simple severity × exploitability model against the OWASP API Security Top 10 (2023):

| Priority | Risk | OWASP Reference |
|---|---|---|
| Critical | Plaintext passwords and SSNs in API responses | API3:2023 BOPLA |
| Critical | No authentication required on destructive operations | API2:2023 Broken Auth |
| Critical | No resource ownership checks (BOLA) | API1:2023 BOLA |
| High | Full user directory accessible without auth | API1:2023, API3:2023 |
| High | No RBAC — any role can call any endpoint | API5:2023 BFLA |
| High | Bank card numbers and IBAN in responses | API3:2023 BOPLA |
| Medium | Unauthenticated access to user sub-resources | API1:2023 |

### Test Oracles

Each test uses one of three classification labels:

- **contract** — asserting documented API behaviour. The test expectation matches what the DummyJSON docs describe.
- **hypothesis** — asserting what production-secure behaviour *should* be. Observed DummyJSON behaviour may differ; the test documents the gap.
- **finding** — asserting a confirmed security gap that is observable and evidenced. The test passes against observed behaviour but emits a named security finding log.

> "Do not change an expected outcome merely to make the suite pass." — The assessment brief. Finding-classified tests assert DummyJSON's actual behaviour (e.g. `200` for an unauthenticated delete) while clearly logging the production expectation (`401`).

---

## Architecture

```
APIAssignment/
├── src/
│   ├── client/              # HTTP client layer — one file per resource
│   │   ├── base.client.ts   # BaseClient wraps Playwright APIRequestContext
│   │   ├── auth.client.ts   # /auth/* endpoints
│   │   ├── users.client.ts  # /users/* endpoints
│   │   ├── products.client.ts
│   │   └── carts.client.ts
│   ├── lib/
│   │   ├── auth-session.ts    # Programmatic token acquisition (reads shared state)
│   │   ├── global-setup.ts    # Runs once — authenticates all users, shares tokens
│   │   ├── global-teardown.ts # Runs once — deletes the temp token file
│   │   └── schemas.ts         # Zod schemas for runtime response validation
│   ├── fixtures/
│   │   └── api.fixtures.ts  # Playwright fixtures — wires clients to tests
│   ├── types/
│   │   └── api.types.ts     # TypeScript interfaces for API shapes
│   ├── utils/
│   │   ├── redact.ts        # Sensitive field redaction for logs
│   │   └── logger.ts        # Structured logger with redaction
│   └── config/
│       └── env.ts           # Environment config loader (fails fast if missing)
├── tests/
│   ├── auth/                # Authentication and token tests
│   ├── rbac/                # Role-based authorisation tests
│   ├── ownership/           # Resource ownership tests
│   ├── schema/              # Schema validation and data exposure
│   ├── negative/            # Boundary and error scenarios
│   └── matrix/              # Data-driven matrix runner
├── data/
│   └── security-matrix.json # External, data-driven test scenario definitions
├── .github/
│   └── workflows/
│       └── api-security-tests.yml
├── .env.example
├── playwright.config.ts
└── package.json
```

### Design Decisions

**Why Playwright APIRequestContext over Axios/Supertest?**
The project already uses Playwright as the test runner. Using its built-in HTTP client avoids a second HTTP library, keeps the dependency count low and provides first-class integration with the HTML reporter.

**Why Zod for schema validation?**
Zod provides TypeScript-native runtime validation with structured error messages. Schema failures include the exact field path and failure reason, making assertion failures immediately understandable — directly satisfying the "make failures understandable" framework expectation.

**Why bounded parallelism (2 workers)?**
The target is a shared public sandbox, so the suite deliberately caps concurrency at 2 workers rather than running unbounded — this keeps request volume gentle while still gaining a speed-up. Authentication is handled once in `global-setup.ts` (three logins total, shared across workers via a temp state file), so parallel workers never duplicate logins or race on token acquisition. `global-teardown.ts` deletes the token file after the run. This is the pattern the framework would use to scale to hundreds of tests.

**Separation of concerns:**
- `BaseClient` handles all HTTP mechanics (headers, response parsing, logging).
- Resource clients (`AuthClient`, `UsersClient` etc.) expose domain-readable methods.
- `AuthSession` manages token lifecycle — tests never handle tokens directly. In parallel runs it reads pre-authenticated tokens established once by `global-setup.ts`, so workers share a single set of tokens rather than each logging in.
- Fixtures inject pre-authenticated contexts into tests — test code reads as business intent.
- The security matrix JSON externalises scenario data so new test cases require no new test logic.

---

## Security Matrix

The security matrix lives at `data/security-matrix.json`. Each entry is a self-documenting scenario:

```json
{
  "id": "OWN-004",
  "area": "Resource Ownership",
  "description": "User updates another user's record via PUT /users/{otherId}",
  "endpoint": "/users/{otherId}",
  "method": "PUT",
  "authContext": "user",
  "resourceOwnership": "other",
  "expectedStatus": 200,
  "productionExpectedStatus": 403,
  "securityClassification": "finding",
  "securityHypothesis": "Users should not be able to modify other users' records. Only admin should have this permission.",
  "priority": "critical"
}
```

To add a new scenario, add a JSON entry. The matrix runner in `tests/matrix/security-matrix.spec.ts` executes all scenarios without any code changes.

---

## Key Findings

These are the material security gaps identified. All are expected and documented for a public sandbox — they would be critical defects in a production system.

### CRITICAL

| ID | Finding | Production Expectation |
|---|---|---|
| EXP-001a | `GET /users/{id}` returns plaintext `password` field | Password must never appear in any API response |
| EXP-001b | `GET /users/{id}` returns `ssn` (Social Security Number) | Omit or mask entirely |
| EXP-001c | `GET /users/{id}` returns `bank.cardNumber` in full | PCI-DSS violation — mask to last 4 digits |
| EXP-001g | `GET /users` returns passwords for all ~208 users unauthenticated | Mass credential exposure endpoint |
| RBAC-003 | `GET /users` returns full user directory without any authentication | 401 required |
| RBAC-005 | `DELETE /users/{id}` succeeds without any authentication | 401 required |
| OWN-002 | Any user can read any other user's cart | 403 — ownership check required |
| OWN-004 | Any user can modify any other user's record | 403 — BOLA vulnerability |

### HIGH

| ID | Finding | Production Expectation |
|---|---|---|
| EXP-001d | `bank.iban` exposed in user response | Omit or mask |
| EXP-001e | `ein` exposed in user response | Omit |
| RBAC-006 | `POST /products/add` accepts unauthenticated writes | 401 required |
| OWN-003 | Cross-user todos access without ownership check | 403 required |

### Assumption: DummyJSON's `/auth/` prefix routes

The `/auth/RESOURCE` pattern (e.g. `GET /auth/users`) does enforce a token check — returning 401 without one. The standard `/users` route does not. This means the auth prefix works as a token validation demonstration but doesn't protect the same data served at the unprefixed routes.

---

## Assumptions and Limitations

### Assumptions

1. **DummyJSON user data is stable enough for test user IDs.** The seeded dataset has been consistent for the duration of development. Tests use IDs 1, 2 and 3 as test targets — if the dataset changes significantly, these may need updating.

2. **The three credential sets provided in `.env` belong to users with distinct IDs.** The ownership tests compare `userSession.userId` vs `secondUserSession.userId` — if they happen to be the same user, ownership tests become vacuous. The README instructs users to configure three distinct accounts.

3. **Simulated CRUD operations.** All write operations on DummyJSON return a success response with an `isDeleted` / modified flag but do not persist changes. Assertions account for this — the framework tests the response contract, not real persistence.

4. **Role classification.** The ADMIN_USERNAME credential is assumed to belong to a user whose `/users/{id}` response shows `"role": "admin"`. If the provided credential belongs to a `user`-role account, the RBAC differentiation tests will still pass but the role-based narrative will be less meaningful.

### Limitations

1. **No real RBAC to test.** DummyJSON does not enforce any role-based access control. All RBAC tests either test the `/auth/` prefix enforcement (which does work) or document the absence of enforcement. This is correctly identified as a sandbox limitation, not a test framework failure.

2. **Refresh token reuse.** The token refresh test uses the same refresh token from the session fixture. DummyJSON does not invalidate used refresh tokens, so refresh token rotation security cannot be tested.

3. **No token expiry testing.** Testing token expiry would require waiting for tokens to expire or manipulating time — neither is practical against a live third-party sandbox with 60-minute default expiry.

4. **Rate limiting.** DummyJSON does not appear to enforce rate limits. Rate limit response validation is out of scope per the operating constraints.

5. **HTTPS enforcement.** The framework always uses `https://dummyjson.com`. Whether HTTP redirects to HTTPS or is simply rejected was not tested.

---

## CI Pipeline

A GitHub Actions workflow at `.github/workflows/api-security-tests.yml` runs the full suite on:
- Push to `main` / `master`
- Pull requests targeting `main` / `master`
- Daily at 06:00 UTC (to catch API drift)

Credentials are stored as GitHub Actions repository secrets (`ADMIN_USERNAME`, `ADMIN_PASSWORD` etc.) — never in the workflow file or repository. The HTML report and results JSON are uploaded as build artifacts retained for 30 days.

On every run the Allure report is regenerated and published to GitHub Pages, giving reviewers a live, browsable report without any local setup:

**https://ambar27-bit.github.io/API-SecurityDummyAssignment/**

To configure: go to your GitHub repository → Settings → Secrets and variables → Actions → New repository secret, and add each key from `.env.example`.

---

## Actual Effort

| Phase | Effort |
|---|---|
| API exploration and strategy design | ~1 hour |
| Framework scaffold and client layer | ~1.5 hours |
| Test implementation | ~2.5 hours |
| Security matrix and findings documentation | ~1 hour |
| CI pipeline and README | ~1 hour |
| **Total** | **~7 hours** |

---

## AI-Assisted Development Disclosure

**Tool used:** Kiro (AI-powered development environment by AWS, built on VS Code)

**How it assisted:**
- Scaffolded the project structure, `package.json`, and configuration files based on the requirements discussed
- Generated the typed API client layer, fixture system and Zod schema definitions
- Assisted in drafting test cases across all test suites
- Generated the security matrix JSON structure and the README

**How output was reviewed and validated:**
- Every generated file was reviewed for correctness of TypeScript types, test logic and security classification accuracy
- The security findings and their severity classifications were independently reasoned against OWASP API Security Top 10 (2023)
- Test assertions were verified against the actual DummyJSON API documentation and behaviour
- The decision not to change expected outcomes to make the suite pass (per the brief) was a deliberate choice made by the candidate — not generated

**What was not AI-generated:**
- The risk prioritisation reasoning and OWASP mapping
- The decision to use `securityClassification: 'finding'` vs `'hypothesis'` — this distinction required judgement about what DummyJSON documents vs what it enforces
- The security finding descriptions and production expectations

I remain responsible for the correctness, security, maintainability and explainability of the complete submission.
