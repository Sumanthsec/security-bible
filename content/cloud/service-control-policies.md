# Service Control Policies (SCPs)
Tags:

## Core

**SCP** = an organization-level policy that lives *outside* accounts (in Organizations) but **restricts which actions are allowed inside** an account — no matter who tries. A preventative **guardrail** ("security blanket").

**Key rule: SCPs do NOT grant permissions.** They only cap what's allowed. To actually do something you still need an identity-based policy that allows it → **two keys**: the SCP must allow the action *and* an identity policy must grant it.

- Default-deny like all AWS policies, so an SCP must include Allow statements — but those say "these actions *may* happen in the account," not *who* may do them.
- **`FullAWSAccess`** is the default allow-all SCP AWS attaches. SCPs don't just *add* restrictions on top of IAM — they define what actions can run in the account *at all*. Attach only deny statements with no allow-all and you take **everything** away — the account breaks instantly.

**Where SCPs sit:** AWS has 6 policy types; the "Big 3":

- **Identity-based** — who can do what → [[iam-policies]]
- **Resource-based** — direct interaction with a resource, incl. from an entity outside your control → [[resource-based-policies]]
- **Organization policies = SCPs** — limit actions in accounts regardless of who

**Details:**

- Defined in the Organizations service; same structure as identity-based policies (some differences, later).
- Attach to **OUs or accounts**. Max **5 per OU/account**.
- **Inherited** down the tree: effective permissions = aggregate granted-and-not-denied across all SCPs above. OUs nest 5 deep → up to 25 + 5 (root) + 5 (account) = **35** applicable.
- Accounts can **move between OUs** → the new branch's SCPs take over. Common pattern: an **account nursery** OU (loose SCPs) for provisioning, then move to a stricter production OU.
- Once enabled, **every OU and account needs an SCP attached**.

**Two strategies:**

- **Deny list** — start allow-all, block what you don't want. More forgiving; most common.
- **Allow list** — start with nothing, build the allowlist. Harder (must know every action needed); worth it for high-value accounts once mature.

## Attack Surface

What SCPs do **NOT** cover (the gaps):

- **Don't affect the management account** — even applied at org root. (Another reason not to run real workloads there → [[aws-organizations]].)
- **Can restrict the root account, but not management.**
- **Don't stop external access to resources** — e.g. a **public S3 bucket**: the access happens outside the account, so the SCP never evaluates it.
- **Don't restrict service-linked roles** (e.g. `AWSServiceRoleForOrganizations`) — so AWS services can't be broken.

## Audit

- SCPs **break things by design** — never deploy one in a production hierarchy without testing and fully understanding the impact.
- Before moving a running account into an OU, **check every SCP on the whole branch** first.

## My Notes
