# api kagi fixture

This fixture exercises running a nested Bun project from `tests/api` while using
the committed fake `.kagi` repository in `tests/.kagi`.

```bash
bun dev
```

`bun dev` calls `kagi run dev bun run index.ts` and reads the committed fake
`dev.MESSAGE` value from `tests/.kagi`. The values in `tests/.kagi` are
test-only and safe to commit; do not copy this pattern for real project secrets.
