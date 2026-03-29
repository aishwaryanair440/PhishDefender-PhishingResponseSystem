## Backend Modules — Deep Dive

### `config.py`
Central configuration file storing all API keys, file
paths, Flask settings, scoring thresholds, and keyword
lists. Every other module imports from here rather than
hardcoding values. This means changing the Flask port,
adding an API key, or adjusting the malicious threshold
requires editing exactly one file.

**Why this approach:** It mirrors the configuration
management patterns used in real production systems
where environment-specific values are always centralized
and never scattered across source files.

---


