# Guarded upgrades and rollback

The installer checkpoints an existing installation before building and deploying. System-mode checkpoints live in `/var/lib/conduit/deployments`; user-mode checkpoints live in `${XDG_STATE_HOME:-$HOME/.local/state}/conduit/deployments`. Checkpoints contain sensitive configuration and CA keys and are restricted to their owner.

Existing binaries, configuration, service units, and system CA files are preserved. New system binaries are staged and renamed atomically while the current processes continue running. Before deployed files change, the installer arms an independent systemd timer. If deployment is not verified within 180 seconds, the timer stops the same installer process (checking its process start time to avoid PID reuse), restores the saved files, reloads units, restarts Conduit, and checks its health.

Installer errors and INT/TERM trigger immediate rollback. The independent timer also covers a killed installer or disconnected terminal. Successful deployment requires both services to be active, healthy API/datastore status, and a real HTTPS request through the proxy. The timer is canceled only after these checks succeed. There is still a brief restart interruption; this is recovery protection, not zero-downtime deployment.

The smoke URL defaults to `https://example.com/`. Set `CONDUIT_DEPLOY_CHECK_URL` to a permitted, known-working HTTPS URL if your policies block that destination. The old installation must pass the smoke test before upgrading.

After a successful upgrade, restore the previous checkpoint with:

```bash
conduit-ctl rollback
```

System mode elevates with sudo. You can also invoke the copied worker from an explicit checkpoint path:

```bash
sudo bash /var/lib/conduit/deployments/checkpoint.EXAMPLE/worker.sh rollback \
  /var/lib/conduit/deployments/checkpoint.EXAMPLE
```

A fresh install has no previous installation to restore. The checkpoint covers the build/deployment phase; it does not undo earlier dependency/datastore installation or later feed seeding, firewall updates, or OS trust-store changes. It does not roll back Valkey contents or dashboard assets. Avoid concurrent installers.

Requirements: Bash, systemd, curl, Python 3.11+, flock, and GNU coreutils. The helper uses explicit proxy flags and keeps the API health check on a direct local connection.

Run the isolated script checks with:

```bash
bash -n scripts/install.sh scripts/conduit-ctl.sh scripts/rollback-deploy.sh scripts/test_rollback.sh
shellcheck -x scripts/rollback-deploy.sh scripts/test_rollback.sh
bash scripts/test_rollback.sh
```

These tests mock service/network operations. They exercise file restoration, permission preservation, absent-file cleanup, failed health checks, late timer cancellation, installer-stop behavior, and manual rollback. They do not restart the installed services.
