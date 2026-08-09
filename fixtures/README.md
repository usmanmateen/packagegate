# Inert analysis fixtures

These packages are **source text for static analysis only**.

Do **not**:

- `node` any file here
- `require` / `import` them
- `npm install` / `pnpm add` them
- run lifecycle scripts

They use non-routable destinations such as `example.invalid` where a hostname
is required in the source.

## Demo

```bash
pnpm packagegate fixture inert-env-exfil --color
pnpm packagegate scan-tarball ./path/to/preserved.tgz
```

See `docs/CLI.md` for registry vs local-tarball integrity semantics.
