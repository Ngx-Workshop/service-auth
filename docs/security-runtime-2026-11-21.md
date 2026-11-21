# Runtime security patch — 2026-11-21

Docker build/runtime stages now use the verified official Node 22.23.5 Alpine image, pinned by digest. CI Node versions are aligned where configured. This is a runtime patch; API contracts and application behavior are unchanged.

Production rollout retains the currently deployed application files on the patched base, preserving host-owned environment, mounts, security settings and container networks. Previous containers/images remain available for rollback. Runtime version and startup probes must pass before recording deployment success. See the Nginx repository security rollout record for cross-service evidence.

Official advisory: https://nodejs.org/en/blog/vulnerability/november-2026-security-releases/
