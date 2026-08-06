# Runtime transport ownership

One scan should reuse one transport instance so pooling, caching, request accounting, and scope decisions are shared. The implementation should lazily create and cache that transport on the scan context to avoid import cycles while preserving a single runtime authority.
