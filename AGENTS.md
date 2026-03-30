## Issue Tracking

This project uses **vardrun** for issue tracking (not GitHub Issues).
When the user says "issue", they mean a vardrun issue.
Run `vardrun prime` for full workflow context — do this at the start of every session.

**Quick reference:**
- `vardrun ready` — find unblocked work
- `vardrun create "Title" --type task --priority 2` — create issue
- `vardrun update <id> --status in_progress` — **take/claim** an issue (auto-assigns you)
- `vardrun update <id> --description "Human-readable summary"` — what the issue is about (for non-developers)
- `vardrun update <id> --implementation @plan.md` — technical implementation details (markdown, for developers)
- `vardrun close <id>` — complete work
- `vardrun show <id> --json` — view issue details (JSON for agents)
- `vardrun list --json` — list all open issues (JSON for agents)
- `vardrun sync` — sync with remote (run after every mutation)

**Taking an issue** = `vardrun update <id> --status in_progress` then `vardrun sync`.
"Take", "claim", "work on", "pick up" all mean this. Always sync after so changes
are visible in the TUI and web interface.

**Completing work:** When committing after finishing an issue, also close it and sync:
```
vardrun close <id>
vardrun sync
git add <files> && git commit -m "..."
git push
```

**For agents:** Use `--json` on any command to discover field structure at runtime.
For full workflow details and all commands: `vardrun prime`
