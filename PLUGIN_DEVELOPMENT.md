# Scanner plugin development

`ScannerPlugin` in `plugins.py` defines metadata and a typed scan operation receiving the managed
root, bounded index, cancellation event, limits, progress callback and optional categories.
Return validated `Finding` models, with evidence references. Never execute target source or follow
links. Emit explicit failures and check cancellation during work.

`examples/readme_plugin.py` is a working trusted offline plugin producing an informative observation
when a README exists but SECURITY.md does not. It is tested and never calls the network.

Register a reviewed local implementation in an embedding script:

```python
from pathlib import Path
from oberhau.engine import Engine, PROFILES
from examples.readme_plugin import SecurityContactPlugin

engine = Engine(Path(".oberhau/plugin-research"))
engine.registry.register(SecurityContactPlugin())
PROFILES["documentation"] = ("Trusted offline security-contact documentation audit", ["security-contact"])
# Import an authorized local project, then engine.scan(project_id, "documentation").
```

This needs no core-module changes. Custom profiles are process-local in this release; the desktop
does not auto-load plugin entry points or internet code. Network/active plugins and duplicate IDs
are rejected. Python plugins are trusted code with operator privileges, not OS-isolated processes;
an isolated plugin host and declarative configuration validation remain future work.
