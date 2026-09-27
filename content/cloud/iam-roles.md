# IAM Roles & Personas
Tags:

## Core

**Persona:** the expression of an identity, with attributes that indicate context. A role is a persona — a named set of permissions an identity takes on. Same identity can hold different roles in different environments (admin in one, read-only in another).

**AWS role = a container for permissions, assumed for a temporary session.** Not just a persona — a *time-limited* set of permissions. Roles are an AWS core primitive; even AWS services use them.

Two policies define a role:

- **Permissions policy** — what the role can do (its max permissions).
- **Trust policy** — who or what may assume it (e.g. IAM user `rmogull`, or a service like CloudTrail).

**Using it:** you need permission to assume the role, and assuming is a deliberate API call → starts a **session** → **temporary credentials** valid only for that session. Switch roles on the fly as the task changes.

**Why roles win** (vs [[iam-users]]):

- No **static credentials** — sessions issue short-lived ones.
- One identity, many personas for different tasks — no username/password per permission combo.
- Mature orgs use roles almost exclusively and drop nearly all IAM users → kills a whole class of lost/stolen/abused-credential attacks.

## Attack Surface


## Audit


## My Notes
