# Daemon responsiveness and supervised restarts

## macOS scheduling

For a launchd deployment serving interactive credential requests, set:

```xml
<key>ProcessType</key>
<string>Interactive</string>
```

`Background` applies CPU and I/O limits. Under contention, a live process and a connectable Unix socket can still fail to answer requests. `Adaptive` promotes jobs through XPC transactions; this daemon uses a Unix socket, not XPC. See the installed `launchd.plist(5)` manual for scheduling semantics.

Do not treat every timeout as scheduling starvation. Capture response timing, process CPU time, load, and the loaded job's scheduling class before restarting. A status timeout alone cannot distinguish scheduling delays from locks or disk waits. Compare an isolated dummy-store process if needed; never change live scheduling to reproduce a failure.

## Check behavior, not just the PID

```sh
secrets --no-update-check --timeout 2 status
```

Record latency and failures across a bounded sample. Verify a real lease only for an authorized credential, with a dedicated client ID and short TTL. Discard the value; do not log it. A successful socket connection or `launchctl print` showing `running` is not an RPC health check.

A lease failure is not a credential value. Check the command's exit status before exporting its output. Do not retry indefinitely or use `revoke --all` to recover a slow daemon.

## Restart versus configuration reload

For routine recovery of a responsive supervised daemon:

```sh
secrets daemon restart
secrets --no-update-check --timeout 2 status
```

If RPC does not answer, use the deployment's approved supervisor recovery path. Do not start a second daemon or widen access to its store.

A launchd `kickstart` restarts the loaded definition. It does **not** reload an edited plist. A configuration change needs this sequence:

1. Back up the current installed plist and validate the replacement with `plutil -lint`.
2. Boot out the exact service target, never the entire domain.
3. Wait for that service definition to disappear before replacing files or bootstrapping.
4. Install and bootstrap the replacement under the same account and permissions.
5. Verify the loaded scheduling class, status latency, and an authorized lease.
6. On failure, restore this operation's backup and verify recovery. Do not report success from bootstrap alone.

`bootout` can return before the old process finishes exiting. An immediate bootstrap can print `5: Input/output error` while the unified launchd log reports `37: Operation already in progress`. Wait on observed removal, not an arbitrary fixed sleep. On macOS, the verified absent-service response is `launchctl print` exit 113 with `Could not find service`; permission failures and other errors are not proof of removal. Bound the wait and fail visibly if teardown cannot be confirmed.

Inspect relevant launchd logs with a narrow time window and service-label filter. Preserve the evidence privately; do not publish raw logs, credentials, or deployment-specific paths.
