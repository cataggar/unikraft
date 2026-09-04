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
  variants, object paths, generated outputs, and exposed dependencies;
- preprocessing outputs, compiler dependency-file paths, and link
  dependencies;
- linker scripts; and
- final debug and image outputs, with auxiliary outputs (such as the compile
  database) identified separately.

Lists and object keys are sorted. Absolute paths below the build, Unikraft,
application, and external library/platform roots use stable placeholders such
as `$BUILD_DIR`, `$UK_BASE`, `$APP_DIR`, and `$LIB_FOO_BASE`. This avoids
embedding checkout-specific paths while preserving path identity.

The Make backend emits an internal ten-column, tab-separated record stream to
`O/.build-graph.records`. `support/scripts/build-graph.py` is the sole
serializer for that explicit format; consumers should use the JSON output and
must not depend on the intermediate records.
