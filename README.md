# AIDID integration registry

The public, machine-readable list of sites that integrate **AIDID** sign-in.

A listing means one thing only: the site **proved it controls its own origin** by
serving a challenge file, and declares that it integrates AIDID. It is **not** a
security review, a reputation signal, or a recommendation. Treat it as a yellow-pages
entry, not an endorsement.

This repository is the **transitional** submission path. The final authority for the
registry is the on-chain registry, which **is not available yet** (no contract is
deployed and the chain-side window parameters have not been released). Until then,
this repository is free and explicitly transitional. Once the on-chain registry is
live, registration moves on-chain and costs **0.01 MSG per registration**.

- Machine-readable snapshot: [`rp-registry.json`](./rp-registry.json)
- Schema: [`schema/rp-registry.schema.json`](./schema/rp-registry.schema.json)
- Validator (node built-ins only): [`scripts/validate-registry.mjs`](./scripts/validate-registry.mjs)
- Human-readable directory and challenge generator: <https://aidid.im/registry/>

---

## How to register (self-service)

1. **Generate a challenge.** Any unguessable value of the form
   `aidid-rp-verify-` + 16–64 lowercase hex characters works, as long as you publish
   exactly the same value. Generate one at <https://aidid.im/registry/> or with:

   ```sh
   node -e "console.log('aidid-rp-verify-' + require('crypto').randomBytes(16).toString('hex'))"
   ```

2. **Publish it on your own domain.** Serve this file over HTTPS:

   ```
   https://<your-origin>/.well-known/aidid-rp.txt
   ```

   Its entire content must be your challenge (a trailing newline is fine). Nothing
   else about your site is touched or checked.

3. **Open a pull request** that adds one entry to [`rp-registry.json`](./rp-registry.json).
   A template and an entry skeleton are provided:

   ```json
   {
     "origin": "https://app.example",
     "name": "Example App",
     "homepage": "https://app.example",
     "did": "did:msg:...",
     "capabilities": ["login"],
     "challenge": "aidid-rp-verify-0123456789abcdef0123456789abcdef",
     "status": "verified",
     "registeredAt": "2026-10-11"
   }
   ```

   `did` is recommended now and **required from on-chain phase 1**.
   `capabilities` and `homepage` are display-only. Only `status: "verified"` entries
   are challenged and published.

### What happens to your pull request

The [`validate-registry`](.github/workflows/validate.yml) workflow:

1. checks the document structure (plain-`https` origin, challenge shape, unique
   origins, known fields);
2. fetches `https://<origin>/.well-known/aidid-rp.txt` for every `verified` entry and
   requires it to equal the registered `challenge`;
3. **merges automatically** (squash) — but only when the pull request changes **exactly
   one file, `rp-registry.json`**, and every challenge was confirmed live.

Anything else is fail-closed: a mismatch, a structural error, a live check that could
not run, or a pull request touching any other file is **not** merged.

> **Fork pull requests — no collaborator access needed:** the workflow runs in this
> repository's context (`pull_request_target`), so its token can merge your pull
> request. You do **not** need an invitation to this repository, an account on our
> side, or a manual review: a verified pull request from a fork is merged exactly like
> any other. The head branch stays in your fork, so we cannot delete it for you.

### Why the automatic merge is safe

`pull_request_target` runs our workflow with a token that can write, so the workflow
deliberately **never executes anything from your pull request**:

- it checks out **this repository only**, at the base commit — never your branch;
- the validator and Node come from this repository: there is no `npm install` /
  `npm ci`, and no script from your pull request is run;
- your `rp-registry.json` is fetched through the GitHub API and treated as **inert
  data** — it is parsed as JSON and compared against a live challenge fetch, never
  executed;
- the only path your pull request is allowed to change is `rp-registry.json`.

If a future change makes the workflow check out a pull request branch, install the
pull request's dependencies, or run a script from the pull request, this safety
argument no longer holds — that change would be a vulnerability.

## Review standard

The only thing reviewed is **control of the origin** (the challenge file). We do not
review, audit, or vouch for the content, privacy practices, or security of a listed
site. To request a takedown or correction, open an issue; the project may suspend an
entry for abuse while keeping the change auditable.

## Relationship to aidid.im

`https://aidid.im/registry/` renders a build-time snapshot of this data, and
`https://aidid.im/registry.json` exposes the machine-readable form. The AIDID site
never reads this repository at runtime — the snapshot is merged and rebuilt by the
project, so the live site stays a static, backend-free export.

`schema/rp-registry.schema.json` is copied from the AIDID site
(`https://aidid.im/schemas/registry/rp-registry.schema.json`); keep it in sync when the
upstream schema changes.

## Validation

```sh
# structure + live challenge checks (used by the workflow)
node scripts/validate-registry.mjs

# structure only
node scripts/validate-registry.mjs --offline
```

## License

The registry data and the validation script are provided under the MIT License — see
[`LICENSE`](./LICENSE). (The AIDID application itself is not licensed by this
repository.)
