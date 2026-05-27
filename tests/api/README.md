# api kagi example

This is a minimal nested Bun service. The app script stays exactly like a user
project:

```bash
bun dev
```

`bun dev` calls `kagi run bun run index.ts`. To try it locally from a fresh
checkout:

```bash
cd tests
kagi init --nested --envs
cd api
kagi set MESSAGE "from kagi"
bun dev
```

The script stays intentionally simple:

```json
"dev": "kagi run bun run index.ts"
```
