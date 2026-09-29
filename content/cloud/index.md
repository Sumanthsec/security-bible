# Cloud Security
Tags:

Map of the cloud section.

## IAM

The 3 core primitives + the terms that tie them together:

- [[identity-fundamentals]] — core terms: entity, identity, identifier, persona, entitlement, AuthN / AuthZ
- [[iam-users]] — identities with **static** credentials & permissions
- [[iam-roles]] — personas with **temporary**, session-based credentials
- [[iam-policies]] — permission policies: identity-based, inline vs managed, JSON structure, evaluation rules

## Policy Types (Big 3)

- [[iam-policies]] — **identity-based**: what a user/role can do
- [[resource-based-policies]] — attached to a resource; controls outside/Internet access (e.g. bucket policies)
- [[service-control-policies]] — **SCPs**: org-level guardrails that cap actions in accounts

## Accounts & Governance

- [[aws-organizations]] — multi-account management: OUs, org roles, Control Tower
- [[service-control-policies]] — SCPs: org-level guardrails that cap actions in accounts (don't grant)

## Storage

- [[s3]] — object storage; #1 source of AWS data leaks; Block Public Access

## My Notes
