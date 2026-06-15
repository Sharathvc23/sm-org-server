# Publishing sm-org-server to PyPI

`sm-org-server` publishes via **PyPI Trusted Publishing** — no API tokens. You tell PyPI
once that this repo's `release.yml` workflow may publish; after that, pushing a
version tag builds and uploads automatically.

> Do this only when `sm-org-server` is meant to be **public**.

## One-time setup (≈5 minutes — this is the part only you can do)

1. Create / sign in to a PyPI account → https://pypi.org/account/register/ (enable 2FA).
2. Go to **https://pypi.org/manage/account/publishing/** → "Add a pending
   publisher" (use *pending*, because the `sm-org-server` project doesn't exist on PyPI
   yet — the first publish creates it).
3. Fill the form with **exactly** these values:

   | Field | Value |
   |-------|-------|
   | PyPI Project Name | `sm-org-server` |
   | Owner | `Sharathvc23` |
   | Repository name | `sm-org-server` |
   | **Workflow name** | `release.yml`  ← just the filename |
   | Environment name | *(leave blank)* |

That's it. No secret is created or stored anywhere.

## Releasing (every time, after setup)

```bash
# bump version in pyproject.toml, commit, then:
git tag v0.1.0
git push origin v0.1.0
```

The `release` workflow builds the sdist + wheel, runs `twine check`, and uploads
to PyPI over OIDC. Watch it under the repo's **Actions** tab. Within a minute,
`pip install sm-org-server` works for everyone.

## Notes

- The tag (`v0.1.0`) and `version` in `pyproject.toml` must match.
- Dry run anytime, no upload: `python -m build && python -m twine check dist/*`.
- To test against TestPyPI first, add a pending publisher on
  https://test.pypi.org and point the publish step at it with
  `with: { repository-url: https://test.pypi.org/legacy/ }`.
- Hardening (optional): set `environment: pypi` on the job + a matching
  Environment name in the PyPI publisher, then require reviewers on that GitHub
  environment so a human approves each release.
