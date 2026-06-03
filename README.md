# libbs (deprecated)

> **`libbs` has been renamed to [`declib`](https://github.com/binsync/declib).**
>
> This package is now a deprecation shim. Installing it will pull in `declib`
> and emit a `DeprecationWarning` on import. No further updates will be made
> to `libbs`.

## Migrate

```bash
pip uninstall libbs
pip install declib
```

Replace `libbs` with `declib` in your imports:

```python
# Before
from libbs.api import DecompilerInterface

# After
from declib.api import DecompilerInterface
```

All sources, docs, examples, and tests now live in the `declib` repository.
