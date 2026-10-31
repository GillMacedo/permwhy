# 0001: One standard-library Python script

**Decision:** all logic is in `scripts/permwhy.py`, using only Python's standard library.

**Why:** a plugin should work right after install, with no dependency step or supply chain to audit. The docs' skill examples use standard-library Python.

**Alternatives:** a real shell parser dependency would handle more syntax, but it would add an install step. When the walker can't split a command, it reports that rather than guessing.
