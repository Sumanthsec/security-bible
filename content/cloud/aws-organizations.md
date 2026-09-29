# AWS Organizations
Tags:

## Core

**AWS Organizations** = an overlay service to manage multiple AWS accounts from one place. (Multi-account is the default in Azure/GCP; in AWS it's opt-in.)

**Why multiple accounts:**

- **Blast radius / isolation** — accounts are absolutely isolated from each other (a hard security boundary). Separate prod / dev / etc.
- **IAM simplicity** — least-privilege is painful to scope in one big shared account; splitting by account reduces IAM complexity.
- **Service limits** — hard caps on resources and API-call volume per account; hit the wall → spin up another account.

**Setup:**

- Promote a normal account to the **management account** — the root of the org.
- **Never host apps or business systems in the management account.** It's extremely powerful — controls the org, billing, account creation, and org-wide policies. An app vulnerability there could hand an attacker the whole organization, not just that app. Keep it clean and dedicated.
- That unlocks:
  - **Organizational Units (OUs)** — folders for accounts (hierarchy).
  - **Service Control Policies (SCPs)** — a new IAM policy type that acts as a guardrail around an account (a permission ceiling / "security blanket"). → [[service-control-policies]]
  - **SSO** via AWS Identity Center, plus centralized management of services like Security Hub.
- Add accounts by **creating** them from the org (hooks auto-configured) or **inviting** existing ones (owner must accept — invite + handshake; you can't steal accounts).
- Account quota starts at 10 (raisable); hard limit in the thousands.

**Two account flavors:**

- **Consolidated Billing** — charges roll up to the management account, otherwise independent. Can't use org security features (no SCPs). Useful to isolate a super-secure account.
- **All Features** — full central management + all governance features.

**Magic roles (All Features):**

- **`AWSServiceRoleForOrganizations`** — a Service-Linked Role: AWS can change its permissions without asking you. Effectively all-powerful; can't delete while the account is in the org.
- **`OrganizationAccountAccessRole`** — created with the AdministratorAccess policy; the default cross-account admin role. Deleting it does *not* break Organizations.

**Control Tower** = AWS service that automates building the org with security guardrails and account-creation automation — does automatically what you can also set up manually.

## Attack Surface

- **Management account = crown jewels** — controls the whole org.
- **`OrganizationAccountAccessRole`** — default cross-account AdministratorAccess; a prime privesc / lateral-movement target.
- **SCPs** set a hard permission ceiling that can deny even admins — matters for both attack and audit.

## Audit


## My Notes
