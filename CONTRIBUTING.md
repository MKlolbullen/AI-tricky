# Contributing

Use Python 3.12 and Node 22. Install `requirements-dev.txt` and run `npm ci`.

Before opening a change, run:

```bash
.venv/bin/python scripts/migrate-catalog.py --check
.venv/bin/python -m pytest backend/tests -q
npm run build
npm test
```

When changing catalog source descriptors, regenerate `src/mini-tricky-catalog.json` with `scripts/migrate-catalog.py`. Preserve attribution, named sockets and explicit readiness restrictions. Add meaningful coverage for new execution behavior or a changed trust boundary.

Do not commit credentials, registered inputs, target responses, local databases or real engagement artifacts. Keep model reasoning separate from execution authority, and preserve native-request versus CLI-launch accounting. Generated fixture output must stay distinguishable from captured observations.

Describe the behavior change and validation in the pull request. Installing a binary is not sufficient evidence that every version of its adapter is compatible.
