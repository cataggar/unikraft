# GNU Make build graph export

The configured GNU Make backend can export its normalized build graph without
building the unikernel:

```sh
make A=/absolute/path/to/app O=/absolute/path/to/build build-graph
```

The target writes `O/build-graph.json` and prints that path. Set
`BUILD_GRAPH_OUTPUT=/absolute/path/file.json` to select another output file.
The target requires an existing configuration, just like `print-libs`.

The JSON document is deterministic and has `schema_version: 1`. It contains:

- target architecture, architecture family, configured image name, and any
  image-name override;
- selected platforms and their registered platform libraries;
- all enabled libraries, source definitions, parsed preprocessing suffixes,
  variants, object and archive inputs, generated outputs, and exposed
  dependencies;
- preprocessing outputs, compiler dependency-file paths, and link
  dependencies;
- linker scripts; and
- final debug and image outputs, with auxiliary outputs (such as the compile
  database) identified separately.

Entity indexes (`libraries` and `platforms`) and object keys are sorted. Arrays
whose order affects linking retain registration order and use stable
first-occurrence de-duplication. These include source variants, library object
and archive inputs, platform libraries, and each platform's `link_stages`.
Link stages describe the actual ordered transformations and their intermediate
outputs. For example, KVM has one `link` stage, while Xen records its
`partial-link`, `objcopy-localize`, and final `link` stages separately.

Absolute paths below the build, Unikraft, application, and external
library/platform roots use stable placeholders. Built-in placeholders are
`$BUILD_DIR`, `$UK_BASE`, and `$APP_DIR`. External component placeholders
encode the component name without loss (for example, library `lib-a` uses
`$LIB_6C69622D61_BASE`) and are described by `path_roots`. This avoids
checkout-specific paths and prevents distinct component names from collapsing
onto one token. Components that intentionally share the same physical root use
one generic `$EXT_..._BASE` token whose `path_roots` entry lists every component
alias, so no shared path is attributed to just one of them.

The Make backend emits an internal ten-column, tab-separated record stream to
`O/.build-graph.records`. `support/scripts/build-graph.py` is the sole
serializer for that explicit format; consumers should use the JSON output and
must not depend on the intermediate records.
