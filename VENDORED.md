# Vendored dependencies

## `sm_arp/`

Vendored from **github.com/Sharathvc23/sm-arp at tag `v0.1.1`** — the canonical
Agency Receipt Protocol library (receipt build / sign / verify / store,
`did:key` identity, JCS canonical bytes, per-issuer hash chain).

### Why it's vendored
`sm-arp` is a **private** repository. A `git+https://…/sm-arp.git@v0.1.1`
dependency can't be cloned by CI (or any fresh checkout) without credentials for
that private repo, which broke every `sm-chapter` build. Vendoring the small,
pinned library in-tree removes the external private fetch entirely — the chapter
wire stays self-hostable from a single clone, which is the whole point of this
repo.

### Scope
Only the package modules are vendored — `__init__.py`, `identity.py`,
`receipts.py`, `store.py` — **not** sm-arp's own test suite. Its one third-party
runtime dependency, `jcs` (RFC 8785), is declared directly in `pyproject.toml`.

### It is upstream's code, kept pristine
`sm_arp/` is excluded from this repo's ruff and strict-mypy gates (see
`pyproject.toml`). Don't edit it here — fix it upstream in sm-arp and re-sync.

### Re-syncing to a new sm-arp release
```bash
git -C <path-to-sm-arp> archive vX.Y.Z \
    sm_arp/__init__.py sm_arp/identity.py sm_arp/receipts.py sm_arp/store.py \
  | tar -x -C <path-to-sm-chapter>/
```
Then bump the pinned version above and re-run the suite. If `sm-arp` is ever
made public again, this can revert to a normal pinned git/PyPI dependency.
