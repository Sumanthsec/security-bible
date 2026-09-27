# IAM Roles & Personas
Tags:

## Core

**Persona:** the expression of an identity, with attributes that indicate context.

Roles are personas. In most systems your role — "user", "admin", "read-only" — is tied to a set of permissions on the back end. The same identity can carry different roles in different environments: `rmogull@securosis.com` might hold the admin role in one environment and read-only in another.

**AWS goes further.** The core concept of a role is the same, but the implementation is very granular and flexible, and used all over AWS — including by Amazon's own services. A role is an AWS core primitive; even AWS services need to use roles and play by their rules.

The trick in AWS: a role is more than a persona — it's a **temporary set of permissions used for a session**. When you create a role you assign:

- **Maximum permissions** — the set of potential permissions the role can grant.
- **A trust policy** — rules on who or what can use the role (e.g. the IAM user `rmogull`, or the AWS service CloudTrail).

That user or service then has to **assume** the role as an active step. The process of assuming a role defines a **session**, and you get a set of **temporary credentials** that only work during that session.

## Attack Surface


## Audit


## My Notes
