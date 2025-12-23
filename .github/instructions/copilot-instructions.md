---
applyTo: "**"
---

## Overview

SpeckEx is an Elixir port of the Speck cipher backed by Rust implementations.
The entrypoint it the `SpeckEx` module, which delegates to `SpeckEx.Block`, `SpeckEx.CTR` and `SpeckEx.AEAD` for implementations.
The actual work is done in `native/speck_ex/src/lib.rs`.

## Docs

Syntax `m::<module_name>` is valid - it is a newer auto-linking feature in ex_doc.
