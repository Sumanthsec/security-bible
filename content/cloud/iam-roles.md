# IAM Roles & Personas
Tags:

## Core

**Persona:** the expression of an identity, with attributes that indicate context. A role is a persona — a named set of permissions an identity takes on. Same identity can hold different roles in different environments (admin in one, read-only in another).

**AWS role = a container for permissions, assumed for a temporary session.** Not just a persona — a *time-limited* set of permissions. Roles are an AWS core primitive; even AWS services use them.

Two policies define a role:

- **Permissions policy** — what the role can do (its max permissions).
- **Trust policy** — who or what may assume it (e.g. IAM user `bulmax`, or a service like CloudTrail).

**Using it:** you need permission to assume the role, and assuming is a deliberate API call → starts a **session** → **temporary credentials** valid only for that session. Switch roles on the fly as the task changes.

**Why roles win** (vs [[iam-users]]):

- No **static credentials** — sessions issue short-lived ones.
- One identity, many personas for different tasks — no username/password per permission combo.
- Mature orgs use roles almost exclusively and drop nearly all IAM users → kills a whole class of lost/stolen/abused-credential attacks.

**Assuming a role (STS):**

- **STS (Security Token Service)** issues the temporary, limited-privilege credentials. The API call is **`sts:AssumeRole`**; default session **1 hour** (console auto-renews up to 24h).
- Two things must line up: the caller needs IAM permission for **`sts:AssumeRole`**, *and* the target role's **trust policy** must allow that principal.
- **Cross-account** — assume a role in another account to operate there (e.g. `OrganizationAccountAccessRole` lets the management account jump into sub-accounts → [[aws-organizations]]).
- **Root can't assume roles** — must use an IAM user or another role.
- **Role chaining** — a role can assume another role.

**Trust-policy gotcha:** a principal of `arn:aws:iam::<account-id>:root` does **not** mean the root user — it means *the whole account* (anything in it). Since root can never assume a role, it effectively means "everyone but root in that account."

## Attack Surface

- **Role chaining** + **cross-account trust** = lateral-movement / privesc paths — follow who can assume what.
- Over-broad trust (`:root` = the entire account) plus a caller holding `sts:AssumeRole` = cross-account access.

## Audit


## My Notes
