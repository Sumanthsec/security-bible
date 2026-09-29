# Resource-Based Policies

Tags:

## Core

**Resource-based policy** = a policy attached *directly to a resource*, controlling who can access it — especially from **outside your account** or the Internet. The third of the "Big 3" policy types alongside [[iam-policies]] (identity-based) and [[service-control-policies]] (SCPs).

**Why they're needed:** some resources can be reached with just a **URL — no API call, no IAM identity** (e.g. an [[s3]] bucket). Identity-based policies and SCPs only apply to API calls, so they're never evaluated for that access. Resource policies fill the gap.

**Bucket policy** = the resource-based policy for S3 (attached to a bucket, protects all objects in it). Written in JSON like IAM policies, but the syntax supports extras like allowing access from a specific IP.

**How they combine (know this):**

- An explicit **deny** in *any* policy (IAM, SCP, or resource) always wins.
- **Same account:** an **allow** in *either* the identity policy *or* the resource policy grants access — you don't need both.
- **Cross-account:** you need an allow in **both** the resource policy (target account) *and* the caller's identity policy — the **"double-arrow" rule**.
- Contrast: IAM + SCP require *both* to allow (AND); resource + IAM (same account) = an allow in *either* is enough.

**Conditions:** resource policies commonly use a `Condition` block to restrict further (e.g. only a specific `aws:SourceArn` or IP). This guards against the **confused-deputy problem** — a service (e.g. CloudTrail) makes the API call on someone's behalf, so without a condition pinning it to *your* account/source, an outsider who knows your resource ARN could point *their* service at your bucket (junk writes = economic DoS; read access = data exposure).

## Attack Surface

- Resource policies are the main way data gets exposed to the Internet → see [[s3]].
- **Confused deputy** — missing `Condition` constraints let a third party abuse a service's access to your resource.
- Same-account: an **allow** on the resource side grants access with no identity-side allow — easy to over-share by accident.

## Audit


## My Notes
