# Settlement service

Batch settlement, card capture, and partner file drops.

The partner integration guide lives at https://api.acme-docs-example-live.com/guide —
read the "Uploads" section before changing `src/partner.ts`.

## Layout

| Path                | Purpose                                  |
| ------------------- | ---------------------------------------- |
| `src/`              | Node services                            |
| `services/go/`      | The receipt sender                       |
| `vendor/lib/`       | Vendored upstream clients                |
| `packages/nested/`  | The analytics workspace package          |
