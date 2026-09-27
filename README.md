# frnsc-artifacts

The [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) definitions (where on a
host each forensic artifact lives) as static Rust data, for the
[`forensic-rs`](https://github.com/ForensicRS/forensic-rs) artifact catalog.

```rust
use forensic_rs::prelude::*;

// Give the pipeline the catalog...
let sources = TriageSources::builder()
    .vfs(vfs)
    .registry(registry)
    .catalog(frnsc_artifacts::catalog())
    .build();

// ...and a parser resolves the definitions it declares, for this host:
let found = ctx.resolve_artifact("WindowsAMCacheHveFile")?;
```

Parsers don't depend on this crate. They name definitions with `Requirement::artifact(..)` from
`forensic-rs`, and whoever builds the pipeline supplies the catalog.

## The data

- `src/generated/` holds every definition of the pinned upstream commit (`KB_COMMIT`), one module
  per upstream YAML file, as `const` Rust values. Nothing is read or parsed at run time.
- `CATALOG` looks definitions up by name or alias (binary search over a generated, sorted index).
- `output_artifact(name)` maps a definition to the `forensic_rs::Artifact` a parser reports for it,
  for the definitions where that is unambiguous (`MAPPED_DEFINITIONS`).

## Regenerating

`src/generated/` is generated; never edit it by hand. To move to a newer upstream commit:

```sh
git -C ../artifacts fetch && git -C ../artifacts checkout <commit>
python3 tools/gen_catalog.py ../artifacts      # needs PyYAML
tools/check_generated.sh ../artifacts          # the checked-in code matches the checkout
cargo test -p frnsc-artifacts
```

The generator fails on anything it doesn't know how to map (a new key, source type, attribute or
OS), so an upstream format change can't be dropped silently. Its output is byte-for-byte
reproducible.

## License

The crate's code is MIT. `src/generated/` is derived from ForensicArtifacts, which is Apache-2.0;
see `NOTICE`.
