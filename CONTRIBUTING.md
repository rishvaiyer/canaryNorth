# Contributing

## Keep the README current with every relevant feature

The `README.md` is the front door and the source of truth for how ContextSeal behaves. **Any change that adds, removes, or alters a user-visible feature must update the README in the same pull request.** A feature that ships without its README update is incomplete, not done.

"Relevant" means anything a user, operator, or reviewer would learn about the system from the README, including:

- A new or changed default (for example, the receipt signing scheme).
- A new or renamed environment variable, flag, or configuration requirement.
- A new or changed API route, request outcome, or response field.
- A new gate, policy check, storage backend, or evidence behavior.
- A changed run, build, or verification command.
- A new production requirement or boot condition.

When you make such a change, before opening the PR:

1. Update every affected README section (feature summary, environment/config, API surface, run and verify steps, repository map, production limits).
2. Grep the README for now-stale claims about what you changed. A default that flipped from off to on must not still read "off by default" anywhere.
3. If the change alters production behavior, state the new requirement explicitly rather than leaving it implicit.

Reviewers should treat a missing or stale README update as a blocking review comment.

## Other checks before a PR

- `node --test` passes.
- `npm run lint` passes.
- No em dash or en dash characters in changed files.
- No secret, signing key, auth token, or evidence-wrapping key is committed.
