# Inert analysis fixtures

These packages are **source text for static analysis only**.

Do **not**:

- `node` any file here
- `require` / `import` them
- `npm install` / `pnpm add` them
- run lifecycle scripts

They use non-routable destinations such as `example.invalid` where a hostname
is required in the source.
