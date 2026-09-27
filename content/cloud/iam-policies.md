# IAM Policies
Tags:

## Core

An IAM **permissions policy** = a list of actions, allowed or denied. Attach it to a user/role and it becomes an [[identity-fundamentals|entitlement]] — what that principal can do.

**Identity-based policies** attach to a user, group, or role and grant/deny permissions. (Resource-based policies also exist — later.) Two subtypes:

- **Inline** — attached to one user/group/role, not reusable. Painful at scale.
- **Managed** — written once, attach anywhere; edits apply instantly to everything using it.
  - **AWS managed** — AWS writes and maintains them.
  - **Customer managed** — you write them; exist only in your account.

**Evaluation rules (know these):**

- **Default deny** — no policy attached = can do nothing.
- Multiple policies combine as a logical sum, deny-prioritized: allowed if *(allowed)* AND *(not denied)*.
- **A single deny beats all allows.** (Full admin + a "Deny RunInstances" policy = can't run instances.)
- `*` **wildcards** are supported — powerful, easy to over-grant.

**Structure (JSON — text only, strict, no comments):**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::bulmax-bucket/*"
        }
    ]
}
```

- **Version** — policy language version; `2012-10-17` is current, required.
- **Statement** — array of statements; each needs Effect + Action + Resource.
- **Effect** — `Allow` or `Deny`.
- **Action** — the API calls (e.g. `s3:GetObject` = read objects, `s3:PutObject` = upload/modify).
- **Resource** — ARN(s) in scope. `arn:aws:s3:::bulmax-bucket/*` = all objects in that bucket.
- **ARN** (Amazon Resource Name) uniquely identifies an AWS resource.

## Attack Surface

- Incredibly granular and easy to mess up; nuances lead to **non-obvious privilege escalation**.
- `*` wildcards → over-permissioning.

## Audit


## My Notes
