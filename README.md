# AtlasCoordinatorService

A local coordinator for an AI tool-execution system, written as a Windows service in C#.

It runs as a Windows service and:

- **Accepts requests over a Named Pipe.** Clients connect to a configured local pipe and send JSON requests. Each request's shape is validated and invalid input is rejected. The pipe accepts only the client SID given in the config.
- **Enforces tier gating and a service-owned tool registry.** Every task carries a tier. Tier 3 and above is blocked. Tools are launched only from the registry in the config, and the task's tier must match the tool's tier.
- **Requires a per-run token.** Each step must have a durable step intent and a matching run token before the service launches or completes it. A stale or foreign token cannot change a task's state.
- **Contains child processes with Windows Job Objects.** Each launched tool is created suspended inside a Job Object configured with kill-on-close. Before the process is resumed, the service rechecks the kill switch, the task state and the token. A child that cannot be terminated is recorded as `termination_pending` rather than reported as stopped.
- **Honors a kill switch.** A marker file named `AGENT_KILL_SWITCH` inside the state root stops new launches and is checked again before resume. Its location is set by the config, and the service rejects a marker path outside its state root. Arming it also terminates running launches. `STOP_STATUS` reports whether it is armed.
- **Journals task state and recovers conservatively.** Step intents and outcomes are written to a per-task journal. If the service stops mid-run, interrupted tasks are marked `outcome_unknown` with reconciliation required, and are not retried silently.

## Current limits

- **Human approval is not implemented.** The approval IPC operations return `APPROVAL_REQUIRED` and make no state change.
- **Console mode skips the SID check.** When run outside the service control manager, the SID lookup is disabled. Run it as a service for production use.
- **Only the orchestration layer is missing.** This repository contains the coordinator component. The component that submits tasks is not included.

## Configuration

The service reads a JSON config file. Its path comes from the `ATLAS_COORDINATOR_CONFIG` environment variable, or defaults to `m0610.config.json` next to the executable. The config defines:

- `state_root`: directory for task state and the journal. It must be inside `allowed_root`.
- `allowed_root`: the root that `state_root` must stay under.
- `stop_marker`: path of the kill-switch file. It must be `AGENT_KILL_SWITCH` inside `state_root`.
- `client_sid`: the SID of the one client allowed to connect to the pipe.
- `pipe_name`: the Named Pipe name.
- `tools`: the tool registry. Each entry sets `exe`, `cwd`, `tier`, and any arguments. Executables must be inside the fixture root, except for the exact System32 binaries `powershell.exe` and `cmd.exe`.

No machine-specific paths are compiled into the code.

## Building

Requires the .NET Framework 4.x compiler (`csc.exe`) on Windows. From the repository root, run:

```
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The executable is written to `bin\AtlasCoordinatorService.exe`. The `bin` folder is not part of the repository.

## License

MIT. See [LICENSE](LICENSE).
