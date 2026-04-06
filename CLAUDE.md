You manage an Obsidian vault called security-bible — a personal offensive security knowledge base stored as a Git repo. The site is published via Quartz v4 at sumanthsec.github.io/security-bible.
Your job is structure, organization, and maintenance — not deciding what content goes where. The user creates content through separate learning sessions and brings it here to be organized.

Note: The Obsidian vault root is `content/`. Open Obsidian pointing at the `content/` directory. Quartz builds from `content/` automatically.

Vault Structure
security-bible/
├── CLAUDE.md                    # This file (repo root)
├── .gitignore
├── quartz.config.ts             # Quartz site config
├── quartz.layout.ts             # Quartz layout config
├── package.json
├── quartz/                      # Quartz source (do not edit)
├── .github/workflows/deploy.yml # GitHub Pages deployment
└── content/                     # ← Obsidian vault root
    ├── index.md                 # Site landing page
    ├── README.md                # Progress tracker
    ├── _templates/
    │   ├── vulnerability.md
    │   ├── how-it-works.md
    │   ├── auditing.md
    │   ├── architecture.md
    │   ├── chain.md
    │   └── case-study.md
    ├── how-it-works/            # How web apps function under the hood
    ├── auditing/                # Testing methodology and workflows
    ├── architecture/            # Application patterns and design
    ├── vulnerabilities/         # One file per vulnerability class
    ├── chains/                  # Multi-vuln attack narratives
    ├── code-patterns/
    │   ├── sinks.md             # Dangerous functions by language
    │   ├── sources.md           # Input entry points by framework
    │   └── fixes.md             # Verified secure patterns
    ├── tooling/
    │   ├── semgrep-rules/       # Custom .yaml rule files
    │   ├── burp-notes.md
    │   └── wireshark-filters.md
    └── case-studies/            # Real-world breach/bug breakdowns
Keep this structure flat — no subdirectories inside the main directories. Obsidian tags and [[links]] handle categorization.
Templates
These are skeletons. The section headings provide structure — the user and their other agents fill in the content. When creating a new note, copy the relevant template and populate whatever the user provides. Leave empty sections with a blank line rather than deleting them.
vulnerability.md
markdown# [Vulnerability Name]
Tags:

## Understand the Feature First

## Why It Exists (Root Cause)

## The Data Flow

## What the Developer Should Have Done

## Exploitation

## What the Vulnerable Code Looks Like

## What the Fix Looks Like

## Chains With

## Key Q&A From This Session

## Lab Work

## Key Insights

## Questions That Came Up

## Links

## My Notes
how-it-works.md
markdown# [Feature/Concept Name]
Tags:

## The Problem This Solves

## How a Developer Implements This

## Why Developers Choose Different Approaches

## What the Code Actually Looks Like

## Configuration and Defaults That Matter

## Where Security Breaks

## Auditing Checklist

## My Notes
auditing.md
markdown# Auditing: [Component/Area]
Tags:

## Mindset Before Touching Anything

## Step 1: Map the Surface

## Step 2: Test Systematically

## Developer Perspective: Why This Is Hard

## Common Patterns in the Wild

## Red Flags During Testing

## Links

## My Notes
architecture.md
markdown# [Architecture Pattern/Concept]
Tags:

## What This Is and Why It Exists

## How It Looks in Practice

## Security Implications

## What to Look For During an Engagement

## Links

## My Notes
chain.md
markdown# [Chain Name]
Tags:

## The Attack Narrative

## Why Each Link Works

## The Developer's Blind Spot

## Detection and Prevention

## Source

## My Notes
case-study.md
markdown# [Case Study Name]
Tags:

## What Happened

## The Attack Chain

## Root Cause Analysis

## What Should Have Prevented This

## Lessons for My Practice

## Links

## My Notes
What You Do
When the user asks to create a note:

Pick the right template based on what they describe
Place it in the correct directory under content/
Use kebab-case filenames (e.g., sql-injection.md, sessions-and-cookies.md)
Use [[wiki-links]] for any cross-references the user mentions

When the user pastes content from another chat:

Organize it into the appropriate template sections
Don't rewrite or editorialize — preserve their language and structure
If content spans multiple note types (e.g., a vuln discussion that also covers how a feature works), split into separate files and link them

When the user asks to update an existing note:

NEVER overwrite ## My Notes — append only
Add new content to the relevant sections
Preserve everything that already exists

When the user asks about git:

Help with commits, pushes, branch management
Suggest meaningful commit messages based on what was changed
Help set up GitHub Pages if requested

When the user asks to restructure:

Move files, rename, merge, or split notes as requested
Update all [[wiki-links]] across the vault that reference renamed/moved files
Update README.md

README.md format:
markdown# Security Bible

## Progress

| Day | Date | Topic | Files |
|-----|------|-------|-------|
| 1 | YYYY-MM-DD | Topic | file1.md, file2.md |

## Stats
- Vulnerabilities: N
- How-it-works: N
- Auditing guides: N
- Chains: N
- Case studies: N
- Semgrep rules: N
Update this whenever files are created or modified.
What You Don't Do

Don't decide what content belongs in which sections — the user or their other agents handle that
Don't add content the user didn't provide
Don't create placeholder notes for topics not yet studied
Don't rewrite or "improve" content the user pastes in
Don't add tags the user didn't specify (suggest them, but let the user confirm)

Initialization
When asked to initialize, create:

All directories under content/
All template files in content/_templates/
content/README.md with empty progress table
content/index.md as the site landing page
content/code-patterns/sinks.md, sources.md, fixes.md with just the H1 title
content/tooling/burp-notes.md and content/tooling/wireshark-filters.md with just the H1 title
.gitignore with: .obsidian/, .trash/, .DS_Store, *.swp, node_modules/, public/, .quartz-cache/
This file as CLAUDE.md

Quartz Commands
- Preview locally: npx quartz build --serve
- Build: npx quartz build
- Deploy: push to main branch (GitHub Actions handles it)
