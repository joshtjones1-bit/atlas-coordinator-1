using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

// Isolated staging broker. The state root, stop marker, fixture root and client SID
// are read from the config file (path in ATLAS_COORDINATOR_CONFIG, default m0610.config.json
// next to the executable).
public sealed class AtlasCoordinatorService : ServiceBase
{
    private const int MaxFrame = 262144;
    private const int GateTimeoutMs = 5000;
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 258;
    private const uint STILL_ACTIVE = 259;

    private static readonly JavaScriptSerializer Json = MakeJson();
    private readonly Mutex gate;
    private readonly Dictionary<string, LaunchRecord> launches = new Dictionary<string, LaunchRecord>(StringComparer.Ordinal);
    private Dictionary<string, object> config;
    private string stateRoot;
    private string fixtureRoot;
    private string stopMarker;
    private string allowedClientSid;
    private string pipeName;
    private volatile bool stopping;
    private Thread listener;
    private NamedPipeServerStream activePipe;
    private bool stateUncertain;
    private bool startupRecoveryComplete;

    private AtlasCoordinatorService()
    {
        ServiceName = "AtlasCoordinator";
        CanStop = true;
        AutoLog = false;
        gate = new Mutex(false, @"Global\AtlasM0610CoordinatorGate");
    }

    protected override void OnStart(string[] args)
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string configPath = Environment.GetEnvironmentVariable("ATLAS_COORDINATOR_CONFIG");
        if (string.IsNullOrEmpty(configPath)) configPath = Path.Combine(baseDir, "m0610.config.json");
        config = ReadObject(File.ReadAllText(configPath, Encoding.UTF8));
        stateRoot = Path.GetFullPath(GetString(config, "state_root"));
        stopMarker = Path.GetFullPath(GetString(config, "stop_marker"));
        allowedClientSid = GetString(config, "client_sid");
        pipeName = GetString(config, "pipe_name");
        if (String.IsNullOrWhiteSpace(allowedClientSid) || String.IsNullOrWhiteSpace(pipeName))
            throw new InvalidDataException("Client SID or pipe name is missing.");

        DirectoryInfo fixture = Directory.GetParent(stateRoot);
        string allowedRoot = Path.GetFullPath(GetString(config, "allowed_root")) + Path.DirectorySeparatorChar;
        if (fixture == null || !fixture.FullName.StartsWith(allowedRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("state_root must be inside the configured allowed_root.");
        fixtureRoot = fixture.FullName;
        if (!String.Equals(stopMarker, Path.Combine(stateRoot, "AGENT_KILL_SWITCH"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixture stop marker must remain inside its isolated state root.");

        string serviceSidName = "NT SERVICE\\" + ServiceName;
        SecurityIdentifier expectedService = null; // SID lookup disabled for console mode
        // SID check skipped for interactive run

        Directory.CreateDirectory(stateRoot);
        foreach (string state in new[] { "pending", "approved", "running", "rejected", "done", "failed", "cancelled", "outcome_unknown", "quarantine", "journal", "launches" })
            Directory.CreateDirectory(Path.Combine(stateRoot, state));

        bool held = false;
        try
        {
            held = gate.WaitOne(GateTimeoutMs);
            if (!held) throw new System.TimeoutException("Startup recovery gate timed out.");
            RecoverTasks();
            startupRecoveryComplete = true;
        }
        finally { if (held) gate.ReleaseMutex(); }

        stopping = false;
        listener = new Thread(ListenLoop);
        listener.IsBackground = true;
        listener.Start();
    }

    protected override void OnStop()
    {
        stopping = true;
        try { if (activePipe != null) activePipe.Dispose(); } catch { }
        try { if (listener != null) listener.Join(3000); } catch { }
        foreach (LaunchRecord launch in launches.Values)
        {
            try { if (launch.Job != IntPtr.Zero) CloseHandle(launch.Job); if (launch.Process != IntPtr.Zero) CloseHandle(launch.Process); } catch { }
        }
        try { gate.Dispose(); } catch { }
    }

    private void ListenLoop()
    {
        while (!stopping)
        {
            NamedPipeServerStream pipe = null;
            try
            {
                PipeSecurity security = new PipeSecurity();
                SecurityIdentifier client = new SecurityIdentifier(allowedClientSid);
                security.AddAccessRule(new PipeAccessRule(client, PipeAccessRights.ReadWrite, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, security);
                activePipe = pipe;
                                pipe.WaitForConnection();
                HandleClient(pipe, null);
            }
            catch (ObjectDisposedException) { }
            catch (IOException) { }
            catch (Exception ex) { Console.Error.WriteLine("LISTEN_ERROR: " + ex.ToString()); }
            finally
            {
                activePipe = null;
                if (pipe != null) pipe.Dispose();
            }
        }
    }

    private void HandleClient(NamedPipeServerStream pipe, string clientSid)
    {
        byte[] header = new byte[4];
        if (!ReadExact(pipe, header, 4)) return;
        int length = BitConverter.ToInt32(header, 0);
        if (length < 2 || length > MaxFrame) return;
        byte[] body = new byte[length];
        if (!ReadExact(pipe, body, length)) return;

        string resolvedSid = null;
        try
        {
            string clientUser = pipe.GetImpersonationUserName();
            if (!string.IsNullOrEmpty(clientUser))
                resolvedSid = new NTAccount(clientUser).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("IMPERSONATION_ERROR: " + ex.Message);
        }

        Dictionary<string, object> request;
        Dictionary<string, object> response;
        try
        {
            request = ReadObject(new UTF8Encoding(false, true).GetString(body));
            if (!String.Equals(resolvedSid, allowedClientSid, StringComparison.OrdinalIgnoreCase))
                response = Error("CALLER_DENIED", "Authenticated caller SID is not allowed.");
            else if (GetInt(request, "protocol_version", 0) != 1)
                response = Error("PROTOCOL_UNSUPPORTED", "Only protocol version 1 is accepted.");
            else
                response = Dispatch(request);
            if (!String.IsNullOrEmpty(GetString(request, "request_id")))
                response["request_id"] = GetString(request, "request_id");
        }
        catch (Exception ex)
        {
            response = Error("REQUEST_INVALID", ex.GetType().Name);
        }
        WriteFrame(pipe, response);
    }

    private Dictionary<string, object> Dispatch(Dictionary<string, object> r)
    {
        string op = GetString(r, "operation");
        if (op == "STOP_STATUS") return Success("STOP_STATUS", new Dictionary<string, object> { { "armed", File.Exists(stopMarker) }, { "state_uncertain", stateUncertain } });
        if (op == "APPROVAL_MUTATE" || op == "STORE_APPROVE")
            return Error("APPROVAL_REQUIRED", "Authenticated human approval IPC is not implemented; no approval mutation was made.");

        bool held = false;
        try
        {
            try { held = gate.WaitOne(GateTimeoutMs); }
            catch (AbandonedMutexException) { held = true; stateUncertain = true; }
            if (!held) return Error("BROKER_BUSY", "Coordinator gate timed out; operation was not started.");
            if (stateUncertain && op != "STOP_ACTIVATE" && op != "STORE_RECOVER")
                return Error("STATE_UNCERTAIN", "Coordinator state is uncertain; only stop activation or conservative recovery is accepted.");
            if (!startupRecoveryComplete && op != "STOP_ACTIVATE" && op != "STORE_RECOVER")
                return Error("RECOVERY_REQUIRED", "Startup recovery has not completed.");

            switch (op)
            {
                case "STORE_CREATE": return CreateTask(r);
                case "STORE_GET": return GetTaskResponse(GetString(r, "task_id"));
                case "STORE_LIST": return ListTasks(GetString(r, "state"));
                case "STORE_REJECT": return MoveTask(r, "pending", "rejected");
                case "STORE_CANCEL": return CancelTask(r);
                case "STORE_CLAIM": return ClaimTask(r);
                case "STORE_FINISH": return FinishTask(r, false);
                case "STORE_UNKNOWN": return FinishTask(r, true);
                case "STORE_SET_TOKEN": return Error("RUN_TOKEN_OWNED_BY_COORDINATOR", "Run tokens are issued only by CLAIM_TASK.");
                case "STORE_ADVANCE": return AdvanceCursor(r);
                case "STORE_RECOVER": return RecoverTasks();
                case "JOURNAL_APPEND": return AppendEvent(r);
                case "JOURNAL_READ": return ReadEvents(r);
                case "STOP_ACTIVATE": return ActivateStop(r);
                case "LAUNCH": return LaunchChild(r);
                case "QUERY_LAUNCH": return QueryLaunch(r);
                case "CANCEL_LAUNCH": return CancelLaunch(r);
                case "READ_OUTPUT": return ReadOutput(r);
                case "JOURNAL_PRUNE": return Error("MAINTENANCE_DISABLED", "Journal pruning is disabled until its retention contract is approved.");
                case "APPROVAL_LIST": return Error("APPROVAL_REQUIRED", "Approval reads are disabled until the authenticated approval path is implemented.");
                default: return Error("OPERATION_DENIED", "Unknown or unsupported operation.");
            }
        }
        catch (Exception ex) { stateUncertain = true; return Error("STATE_OPERATION_FAILED", ex.ToString()); }
        finally { if (held) { try { gate.ReleaseMutex(); } catch { stateUncertain = true; } } }
    }

    private Dictionary<string, object> CreateTask(Dictionary<string, object> r)
    {
        if (r.ContainsKey("plan") && r["plan"] is ArrayList && ((ArrayList)r["plan"]).Count > 0)
            return Error("PLAN_NOT_SUPPORTED", "This isolated M06.10 fixture supports only single-step tasks.");
        string tool = GetString(r, "tool");
        int tier = GetInt(r, "tier", 0);
        if (String.IsNullOrWhiteSpace(tool) || tool.Length > 64 || tier < 1 || tier > 3)
            return Error("REQUEST_INVALID", "Task tool or tier is invalid.");
        string id = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        string now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        Dictionary<string, object> rec = new Dictionary<string, object> {
            { "id", id }, { "created", now }, { "updated", now }, { "tool", tool },
            { "args", r.ContainsKey("args") ? r["args"] : "" }, { "tier", tier }, { "status", "pending" },
            { "requested_by", "authenticated-ipc" }, { "approved_by", null }, { "approved_at", null },
            { "result", null }, { "error", null }, { "schema", 1 }, { "log", new ArrayList { new Dictionary<string, object> { { "ts", now }, { "event", "created" } } } }
        };
        WriteTask("pending", id, rec);
        return Success("STORE_CREATE", new Dictionary<string, object> { { "task_id", id }, { "record", rec } });
    }

    private Dictionary<string, object> GetTaskResponse(string id)
    {
        string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec)) return Success("STORE_GET", new Dictionary<string, object> { { "state", null }, { "record", null } });
        return Success("STORE_GET", new Dictionary<string, object> { { "state", state }, { "record", rec } });
    }

    private Dictionary<string, object> ListTasks(string requestedState)
    {
        ArrayList result = new ArrayList();
        string[] states = String.IsNullOrEmpty(requestedState) ? new[] { "pending", "approved", "running", "rejected", "done", "failed", "cancelled", "outcome_unknown" } : new[] { requestedState };
        foreach (string state in states)
        {
            if (!ValidState(state)) continue;
            string dir = Path.Combine(stateRoot, state);
            foreach (string path in Directory.GetFiles(dir, "*.json"))
            {
                Dictionary<string, object> rec = ReadObject(File.ReadAllText(path, Encoding.UTF8));
                result.Add(new Dictionary<string, object> { { "state", state }, { "record", rec } });
            }
        }
        return Success("STORE_LIST", new Dictionary<string, object> { { "tasks", result } });
    }

    private Dictionary<string, object> MoveTask(Dictionary<string, object> r, string from, string to)
    {
        string id = GetString(r, "task_id"); string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || state != from) return Error("TASK_STATE_MISMATCH", "Task is not in the expected state.");
        rec["status"] = to; rec["updated"] = UtcNow();
        if (to == "rejected") { rec["rejected_by"] = "authenticated-ipc"; rec["rejected_at"] = UtcNow(); }
        rec["log"] = AppendLog(rec, "moved to " + to);
        MoveRecord(from, to, id, rec);
        return Success("STORE_REJECT", new Dictionary<string, object> { { "record", rec } });
    }

    private Dictionary<string, object> CancelTask(Dictionary<string, object> r)
    {
        string id = GetString(r, "task_id"); string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || (state != "pending" && state != "approved")) return Error("TASK_STATE_MISMATCH", "Only pending or approved tasks can be cancelled.");
        rec["status"] = "cancelled"; rec["cancelled_by"] = "authenticated-ipc"; rec["cancelled_at"] = UtcNow(); rec["updated"] = UtcNow(); rec["log"] = AppendLog(rec, "cancelled");
        MoveRecord(state, "cancelled", id, rec);
        return Success("STORE_CANCEL", new Dictionary<string, object> { { "record", rec } });
    }

    private Dictionary<string, object> ClaimTask(Dictionary<string, object> r)
    {
        if (File.Exists(stopMarker)) return Error("KILL_SWITCH_ARMED", "Stop is engaged.");
        string id = GetString(r, "task_id"); string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || state != "approved") return Error("TASK_NOT_APPROVED", "Task is not approved.");
        int tier = GetInt(rec, "tier", 99);
        if (tier >= 3) return Error("TIER_BLOCKED", "Tier 3+ remains unconditionally blocked.");
        if (tier < 1 || rec.ContainsKey("reconciliation_required") && Object.Equals(rec["reconciliation_required"], true)) return Error("TASK_STATE_UNCERTAIN", "Task cannot be safely claimed.");
        string token = Guid.NewGuid().ToString("N");
        rec["status"] = "running"; rec["executed_at"] = UtcNow(); rec["updated"] = UtcNow(); rec["run_token"] = token; rec["log"] = AppendLog(rec, "claimed by coordinator");
        MoveRecord("approved", "running", id, rec);
        return Success("STORE_CLAIM", new Dictionary<string, object> { { "record", rec }, { "run_token", token } });
    }

    private Dictionary<string, object> FinishTask(Dictionary<string, object> r, bool unknown)
    {
        string id = GetString(r, "task_id"); string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || state != "running") return Error("TASK_STATE_MISMATCH", "Task is not running.");
        string token = GetString(r, "run_token");
        if (!TokenMatches(rec, token)) return Error("RUN_TOKEN_STALE", "Run token does not match the active claim.");
        bool success = !unknown && GetBool(r, "success", false);
        string target = unknown ? "outcome_unknown" : (success ? "done" : "failed");
        rec["status"] = target; rec["updated"] = UtcNow(); rec["finished_at"] = UtcNow(); rec["result"] = r.ContainsKey("result") ? r["result"] : null;
        if (unknown) { rec["outcome"] = "dispatch_unknown"; rec["reconciliation_required"] = true; }
        if (r.ContainsKey("error")) rec["error"] = r["error"];
        rec["run_token"] = null; rec["log"] = AppendLog(rec, "finished " + target);
        MoveRecord("running", target, id, rec);
        return Success(unknown ? "STORE_UNKNOWN" : "STORE_FINISH", new Dictionary<string, object> { { "record", rec } });
    }

    private Dictionary<string, object> AdvanceCursor(Dictionary<string, object> r)
    {
        string id = GetString(r, "task_id"); string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || state != "running" || !TokenMatches(rec, GetString(r, "run_token"))) return Error("RUN_TOKEN_STALE", "Task is not owned by this run.");
        int cursor = GetInt(rec, "cursor", 0); int expected = GetInt(r, "expected_cursor", -1);
        if (cursor != expected) return Error("STEP_MISMATCH", "Cursor changed.");
        string step = GetString(r, "step_id");
        if (!HasVerifiedEvent(id, step)) return Error("CHECKPOINT_UNVERIFIED", "Journal does not prove this step verified successfully.");
        rec["cursor"] = cursor + 1; rec["updated"] = UtcNow(); rec["log"] = AppendLog(rec, "checkpoint advanced"); WriteTask(state, id, rec);
        AppendEventInternal(id, "checkpoint", new Dictionary<string, object> { { "step", step }, { "cursor", cursor + 1 } });
        return Success("STORE_ADVANCE", new Dictionary<string, object> { { "cursor", cursor + 1 }, { "record", rec } });
    }

    private Dictionary<string, object> RecoverTasks()
    {
        ArrayList resolved = new ArrayList();
        string dir = Path.Combine(stateRoot, "running");
        foreach (string path in Directory.GetFiles(dir, "*.json"))
        {
            string id = Path.GetFileNameWithoutExtension(path); Dictionary<string, object> rec = ReadObject(File.ReadAllText(path, Encoding.UTF8));
            rec["status"] = "outcome_unknown"; rec["outcome"] = "dispatch_unknown"; rec["reconciliation_required"] = true; rec["run_token"] = null; rec["finished_at"] = UtcNow(); rec["updated"] = UtcNow(); rec["error"] = "Coordinator recovery conservatively classified the interrupted run as unknown.";
            rec["log"] = AppendLog(rec, "recovery outcome_unknown");
            MoveRecord("running", "outcome_unknown", id, rec); resolved.Add(id);
        }
        if (!stateUncertain) startupRecoveryComplete = true;
        return Success("STORE_RECOVER", new Dictionary<string, object> { { "recovered", resolved }, { "state_uncertain", stateUncertain } });
    }

    private Dictionary<string, object> AppendEvent(Dictionary<string, object> r)
    {
        string id = GetString(r, "task_id"); string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || state != "running" || !TokenMatches(rec, GetString(r, "run_token"))) return Error("RUN_TOKEN_STALE", "Journal write is not owned by the active task run.");
        string ev = GetString(r, "event");
        if (!new[] { "step_intent", "step_not_dispatched", "step_result", "step_verified", "checkpoint", "recovery", "step_refused", "launch_registered", "launch_resumed", "launch_exit", "launch_unknown" }.Contains(ev)) return Error("EVENT_DENIED", "Unknown journal event type.");
        Dictionary<string, object> fields = r.ContainsKey("fields") ? AsDictionary(r["fields"]) : new Dictionary<string, object>();
        Dictionary<string, object> result = AppendEventInternal(id, ev, fields);
        return Success("JOURNAL_APPEND", new Dictionary<string, object> { { "event", result } });
    }

    private Dictionary<string, object> ReadEvents(Dictionary<string, object> r)
    {
        string id = GetString(r, "task_id"); string path = JournalPath(id);
        ArrayList events = new ArrayList();
        if (File.Exists(path))
        {
            string[] lines = File.ReadAllLines(path, Encoding.UTF8);
            foreach (string line in lines) { try { events.Add(ReadObject(line)); } catch { return Error("JOURNAL_CORRUPT", "Journal contains malformed data."); } }
        }
        return Success("JOURNAL_READ", new Dictionary<string, object> { { "events", events } });
    }

    private Dictionary<string, object> ActivateStop(Dictionary<string, object> r)
    {
        string parent = Path.GetDirectoryName(stopMarker); Directory.CreateDirectory(parent);
        string tmp = stopMarker + ".tmp." + Guid.NewGuid().ToString("N");
        using (FileStream fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (StreamWriter w = new StreamWriter(fs, new UTF8Encoding(false))) { w.Write(UtcNow() + " " + Truncate(GetString(r, "reason"), 400)); w.Flush(); fs.Flush(true); }
        if (File.Exists(stopMarker)) File.Delete(tmp); else File.Move(tmp, stopMarker);
        bool complete = true;
        foreach (LaunchRecord launch in launches.Values)
        {
            if (launch.Status != "running") continue;
            if (!TerminateJobObject(launch.Job, 0xE0000002) || WaitForSingleObject(launch.Process, 5000) != WAIT_OBJECT_0) { complete = false; launch.Status = "termination_pending"; }
            else { launch.Status = "terminated"; launch.ExitCode = unchecked((int)0xE0000002); }
        }
        return Success("STOP_ACTIVATE", new Dictionary<string, object> { { "armed", true }, { "termination", complete ? "verified" : "pending" } });
    }

    private Dictionary<string, object> LaunchChild(Dictionary<string, object> r)
    {
        if (File.Exists(stopMarker)) return Error("KILL_SWITCH_ARMED", "Stop is engaged.");
        string id = GetString(r, "task_id"), tool = GetString(r, "tool_id"), step = GetString(r, "step_id"), token = GetString(r, "run_token");
        string state; Dictionary<string, object> rec;
        if (!FindTask(id, out state, out rec) || state != "running" || !TokenMatches(rec, token)) return Error("RUN_TOKEN_STALE", "Task is not owned by this run.");
        if (GetInt(rec, "tier", 99) >= 3) return Error("TIER_BLOCKED", "Tier 3+ is unconditionally blocked.");
        if (!String.Equals(GetString(rec, "tool"), tool, StringComparison.Ordinal)) return Error("TOOL_NOT_ALLOWED", "Requested tool does not match the task record.");
        string storedPlanHash = GetString(rec, "plan_hash");
        string requestedPlanHash = GetString(r, "plan_hash");
        if (!String.IsNullOrEmpty(storedPlanHash) && !String.Equals(storedPlanHash, requestedPlanHash, StringComparison.Ordinal))
            return Error("PLAN_HASH_MISMATCH", "Requested plan hash does not match the stored task record.");
        Dictionary<string, object> toolMap = config.ContainsKey("tools") ? AsDictionary(config["tools"]) : new Dictionary<string, object>();
        if (!toolMap.ContainsKey(tool)) return Error("TOOL_NOT_ALLOWED", "Tool is not in the service-owned registry.");
        Dictionary<string, object> toolSpec = AsDictionary(toolMap[tool]);
        if (GetInt(toolSpec, "tier", 99) >= 3 || GetInt(toolSpec, "tier", 99) != GetInt(rec, "tier", -1)) return Error("TIER_BLOCKED", "Tool/record tier mismatch or Tier 3+.");
        if (!HasIntent(id, step, token)) return Error("STEP_MISMATCH", "Durable step_intent is missing.");

        string exe = Path.GetFullPath(GetString(toolSpec, "exe"));
        string cwd = Path.GetFullPath(GetString(toolSpec, "cwd"));
        string fixturePrefix = fixtureRoot + Path.DirectorySeparatorChar;
        // Only the exact System32 binaries below may run from outside the fixture root.
        bool isSystemPowerShell = IsAllowedSystemBinary(exe);
        if (!isSystemPowerShell && (!exe.StartsWith(fixturePrefix, StringComparison.OrdinalIgnoreCase) ||
            !cwd.StartsWith(fixturePrefix, StringComparison.OrdinalIgnoreCase)))
            return Error("TOOL_NOT_ALLOWED", "This broker build may launch only fixture files under its staging directory.");
        if (!File.Exists(exe) || !Directory.Exists(cwd)) return Error("TOOL_NOT_ALLOWED", "Allowlisted executable or working directory is unavailable.");
        string launchId = Guid.NewGuid().ToString("N");
        LaunchRecord launch = CreateContainedProcess(launchId, exe, cwd, toolSpec, GetString(rec, "args"), id, step, token);
        launches.Add(launchId, launch);
        return Success("LAUNCH", new Dictionary<string, object> { { "launch_id", launchId }, { "pid", launch.Pid }, { "created_utc", launch.CreatedUtc }, { "image", exe }, { "status", launch.Status } });
    }

    private static readonly string[] AllowedSystemBinaries = { "powershell.exe", "cmd.exe" };

    private static bool IsAllowedSystemBinary(string exe)
    {
        string systemDir = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.System));
        string dir = Path.GetDirectoryName(exe);
        if (String.IsNullOrEmpty(dir) || !String.Equals(Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar), systemDir.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            return false;
        string name = Path.GetFileName(exe);
        return AllowedSystemBinaries.Any(b => String.Equals(b, name, StringComparison.OrdinalIgnoreCase));
    }

    private LaunchRecord CreateContainedProcess(string launchId, string exe, string cwd, Dictionary<string, object> toolSpec, string taskArgs, string taskId, string stepId, string token)
    {
        IntPtr job = IntPtr.Zero, attrs = IntPtr.Zero, jobList = IntPtr.Zero, process = IntPtr.Zero, thread = IntPtr.Zero;
        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null); Check(job, "CreateJobObjectW");
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))) ThrowLast("SetInformationJobObject");
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == IntPtr.Zero) ThrowLast("InitializeProcThreadAttributeList(size)");
            attrs = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attrs, 1, 0, ref size)) ThrowLast("InitializeProcThreadAttributeList");
            jobList = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobList, job);
            if (!UpdateProcThreadAttribute(attrs, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_JOB_LIST), jobList, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) ThrowLast("UpdateProcThreadAttribute(JOB_LIST)");

            string arguments = "";
            if (toolSpec.ContainsKey("fixed_args")) foreach (object a in (ArrayList)toolSpec["fixed_args"]) arguments += " " + Quote(Convert.ToString(a, CultureInfo.InvariantCulture));
            if (GetBool(toolSpec, "pass_task_args", false) && !String.IsNullOrEmpty(taskArgs)) arguments += " " + Quote(taskArgs);
            string command = Quote(exe) + arguments;
            STARTUPINFOEX startup = new STARTUPINFOEX(); startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX)); startup.lpAttributeList = attrs;
            PROCESS_INFORMATION pi;
            if (!CreateProcessW(exe, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, cwd, ref startup, out pi)) ThrowLast("CreateProcessW");
            process = pi.hProcess; thread = pi.hThread;
            bool inJob;
            if (!IsProcessInJob(process, job, out inJob) || !inJob) { TerminateProcess(process, 0xE0000003); throw new InvalidOperationException("Creation-time Job membership was not verified."); }

            AppendEventInternal(taskId, "launch_registered", new Dictionary<string, object> { { "launch_id", launchId }, { "step", stepId }, { "pid", pi.dwProcessId }, { "image", exe }, { "state", "contained_suspended" } });
            string state; Dictionary<string, object> rec;
            if (File.Exists(stopMarker) || !FindTask(taskId, out state, out rec) || state != "running" || !TokenMatches(rec, token) || !HasIntent(taskId, stepId, token))
            { TerminateJobObject(job, 0xE0000004); WaitForSingleObject(process, 5000); AppendEventInternal(taskId, "launch_unknown", new Dictionary<string, object> { { "launch_id", launchId }, { "reason", "revalidation_failed_before_resume" } }); throw new InvalidOperationException("Authorization changed before resume; child was terminated while suspended."); }
            uint prior = ResumeThread(thread);
            if (prior == UInt32.MaxValue || prior != 1) { TerminateJobObject(job, 0xE0000005); WaitForSingleObject(process, 5000); ThrowLast("ResumeThread"); }
            AppendEventInternal(taskId, "launch_resumed", new Dictionary<string, object> { { "launch_id", launchId }, { "pid", pi.dwProcessId } });
            LaunchRecord result = new LaunchRecord { Id = launchId, Job = job, Process = process, Pid = pi.dwProcessId, CreatedUtc = UtcNow(), Image = exe, Status = "running", TaskId = taskId, StepId = stepId, RunToken = token };
            job = IntPtr.Zero; process = IntPtr.Zero;
            return result;
        }
        finally
        {
            if (thread != IntPtr.Zero) CloseHandle(thread);
            if (process != IntPtr.Zero) CloseHandle(process);
            if (job != IntPtr.Zero) CloseHandle(job);
            if (attrs != IntPtr.Zero) { DeleteProcThreadAttributeList(attrs); Marshal.FreeHGlobal(attrs); }
            if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
        }
    }

    private Dictionary<string, object> QueryLaunch(Dictionary<string, object> r)
    {
        LaunchRecord launch;
        if (!launches.TryGetValue(GetString(r, "launch_id"), out launch)) return Error("LAUNCH_NOT_FOUND", "Unknown launch id.");
        if (launch.Status == "running" && WaitForSingleObject(launch.Process, 0) == WAIT_OBJECT_0)
        {
            uint code; if (!GetExitCodeProcess(launch.Process, out code)) return Error("CHILD_IDENTITY_UNCERTAIN", "Cannot read child exit status.");
            launch.ExitCode = unchecked((int)code); launch.Status = "exited";
            AppendEventInternal(launch.TaskId, "launch_exit", new Dictionary<string, object> { { "launch_id", launch.Id }, { "exit_code", launch.ExitCode } });
            CloseHandle(launch.Job); launch.Job = IntPtr.Zero; if (launch.Process != IntPtr.Zero) { CloseHandle(launch.Process); launch.Process = IntPtr.Zero; } if (launch.Process != IntPtr.Zero) { CloseHandle(launch.Process); launch.Process = IntPtr.Zero; }
        }
        return Success("QUERY_LAUNCH", new Dictionary<string, object> { { "launch_id", launch.Id }, { "pid", launch.Pid }, { "status", launch.Status }, { "exit_code", launch.ExitCode } });
    }

    private Dictionary<string, object> CancelLaunch(Dictionary<string, object> r)
    {
        LaunchRecord launch;
        if (!launches.TryGetValue(GetString(r, "launch_id"), out launch)) return Error("LAUNCH_NOT_FOUND", "Unknown launch id.");
        if (launch.Status != "running") return Success("CANCEL_LAUNCH", new Dictionary<string, object> { { "status", launch.Status } });
        if (!TerminateJobObject(launch.Job, 0xE0000006) || WaitForSingleObject(launch.Process, 5000) != WAIT_OBJECT_0) { launch.Status = "termination_pending"; return Error("STOP_TERMINATION_PENDING", "Child termination was not verified."); }
        launch.Status = "terminated"; uint code; GetExitCodeProcess(launch.Process, out code); launch.ExitCode = unchecked((int)code); CloseHandle(launch.Job); launch.Job = IntPtr.Zero; if (launch.Process != IntPtr.Zero) { CloseHandle(launch.Process); launch.Process = IntPtr.Zero; } if (launch.Process != IntPtr.Zero) { CloseHandle(launch.Process); launch.Process = IntPtr.Zero; }
        return Success("CANCEL_LAUNCH", new Dictionary<string, object> { { "status", launch.Status }, { "exit_code", launch.ExitCode } });
    }

    private Dictionary<string, object> ReadOutput(Dictionary<string, object> r)
    {
        return Success("READ_OUTPUT", new Dictionary<string, object> { { "stdout", "" }, { "stderr", "" }, { "status", "not_captured_in_m0610_fixture" } });
    }

    private Dictionary<string, object> AppendEventInternal(string taskId, string ev, Dictionary<string, object> fields)
    {
        string path = JournalPath(taskId); Directory.CreateDirectory(Path.GetDirectoryName(path));
        int seq = 1;
        if (File.Exists(path))
        {
            string[] lines = File.ReadAllLines(path, Encoding.UTF8);
            if (lines.Length > 0) { Dictionary<string, object> last = ReadObject(lines[lines.Length - 1]); seq = GetInt(last, "seq", lines.Length) + 1; }
        }
        Dictionary<string, object> item = new Dictionary<string, object> { { "seq", seq }, { "ts", UtcNow() }, { "event", ev } };
        foreach (KeyValuePair<string, object> kv in fields) item[kv.Key] = kv.Value;
        string line = Json.Serialize(item) + "\n";
        using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        using (StreamWriter w = new StreamWriter(fs, new UTF8Encoding(false))) { w.Write(line); w.Flush(); fs.Flush(true); }
        return item;
    }

    private bool HasIntent(string taskId, string stepId, string token)
    {
        string path = JournalPath(taskId); if (!File.Exists(path)) return false;
        foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
        {
            Dictionary<string, object> e; try { e = ReadObject(line); } catch { return false; }
            if (GetString(e, "event") == "step_intent" && GetString(e, "step") == stepId && GetString(e, "run_token") == token) return true;
        }
        return false;
    }

    private bool HasVerifiedEvent(string taskId, string stepId)
    {
        string p = JournalPath(taskId); if (!File.Exists(p)) return false;
        foreach (string line in File.ReadAllLines(p, Encoding.UTF8))
        { Dictionary<string, object> e; try { e = ReadObject(line); } catch { return false; } if (GetString(e, "event") == "step_verified" && GetString(e, "step") == stepId && GetString(e, "verify_status") == "ok") return true; }
        return false;
    }

    private void WriteTask(string state, string id, Dictionary<string, object> rec)
    {
        if (!ValidState(state) || String.IsNullOrWhiteSpace(id) || id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) throw new InvalidDataException("Invalid task path.");
        string dir = Path.Combine(stateRoot, state); Directory.CreateDirectory(dir); string path = Path.Combine(dir, id + ".json");
        string tmp = path + ".tmp." + Guid.NewGuid().ToString("N");
        using (FileStream fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (StreamWriter w = new StreamWriter(fs, new UTF8Encoding(false))) { w.Write(Json.Serialize(rec)); w.Flush(); fs.Flush(true); }
        if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
    }

    private void MoveRecord(string from, string to, string id, Dictionary<string, object> rec)
    {
        if (!new[] { "pending>approved", "pending>rejected", "pending>cancelled", "approved>running", "approved>cancelled", "running>done", "running>failed", "running>outcome_unknown" }.Contains(from + ">" + to)) throw new InvalidOperationException("Invalid state transition.");
        string src = Path.Combine(stateRoot, from, id + ".json"); string dst = Path.Combine(stateRoot, to, id + ".json");
        if (File.Exists(dst)) throw new IOException("Destination state already exists.");
        WriteTask(to, id, rec); File.Delete(src);
    }

    private bool FindTask(string id, out string state, out Dictionary<string, object> rec)
    {
        state = null; rec = null;
        if (String.IsNullOrWhiteSpace(id) || id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return false;
        foreach (string s in new[] { "pending", "approved", "running", "rejected", "done", "failed", "cancelled", "outcome_unknown" })
        {
            string p = Path.Combine(stateRoot, s, id + ".json"); if (!File.Exists(p)) continue;
            if (state != null) throw new InvalidDataException("Duplicate task records across states.");
            rec = ReadObject(File.ReadAllText(p, Encoding.UTF8)); state = s;
        }
        return state != null;
    }

    private ArrayList AppendLog(Dictionary<string, object> rec, string eventName)
    {
        ArrayList log = rec.ContainsKey("log") && rec["log"] is ArrayList ? (ArrayList)rec["log"] : new ArrayList();
        log.Add(new Dictionary<string, object> { { "ts", UtcNow() }, { "event", eventName } }); return log;
    }

    private string JournalPath(string id)
    {
        if (String.IsNullOrWhiteSpace(id) || id.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) throw new InvalidDataException("Invalid task id.");
        return Path.Combine(stateRoot, "journal", id + ".jsonl");
    }

    private bool TokenMatches(Dictionary<string, object> rec, string token) { return !String.IsNullOrEmpty(token) && GetString(rec, "run_token") == token; }
    private static string UtcNow() { return DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture); }
    private static string Truncate(string s, int n) { return String.IsNullOrEmpty(s) ? "" : s.Substring(0, Math.Min(s.Length, n)); }
    private static bool ValidState(string s) { return new[] { "pending", "approved", "running", "rejected", "done", "failed", "cancelled", "outcome_unknown", "quarantine" }.Contains(s); }
    private static JavaScriptSerializer MakeJson() { JavaScriptSerializer j = new JavaScriptSerializer(); j.MaxJsonLength = MaxFrame; return j; }
    private static Dictionary<string, object> ReadObject(string s) { Dictionary<string, object> d = Json.Deserialize<Dictionary<string, object>>(s); if (d == null) throw new InvalidDataException("JSON object required."); return d; }
    private static Dictionary<string, object> AsDictionary(object o) { Dictionary<string, object> d = o as Dictionary<string, object>; if (d == null) throw new InvalidDataException("JSON object required."); return d; }
    private static string GetString(Dictionary<string, object> d, string key) { object v; return d != null && d.TryGetValue(key, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : ""; }
    private static int GetInt(Dictionary<string, object> d, string key, int fallback) { object v; if (d == null || !d.TryGetValue(key, out v) || v == null) return fallback; int x; return Int32.TryParse(Convert.ToString(v, CultureInfo.InvariantCulture), out x) ? x : fallback; }
    private static bool GetBool(Dictionary<string, object> d, string key, bool fallback) { object v; return d != null && d.TryGetValue(key, out v) ? Convert.ToBoolean(v, CultureInfo.InvariantCulture) : fallback; }
    private static Dictionary<string, object> Success(string code, Dictionary<string, object> data) { data["ok"] = true; data["code"] = code; data["protocol_version"] = 1; return data; }
    private static Dictionary<string, object> Error(string code, string message) { return new Dictionary<string, object> { { "ok", false }, { "code", code }, { "message", message }, { "protocol_version", 1 } }; }
    private static bool ReadExact(Stream s, byte[] b, int count) { int p = 0; while (p < count) { int n = s.Read(b, p, count - p); if (n <= 0) return false; p += n; } return true; }
    private static void WriteFrame(Stream s, Dictionary<string, object> d) { byte[] b = Encoding.UTF8.GetBytes(Json.Serialize(d)); if (b.Length > MaxFrame) throw new InvalidDataException("Response too large."); byte[] h = BitConverter.GetBytes(b.Length); s.Write(h, 0, h.Length); s.Write(b, 0, b.Length); s.Flush(); }
    private static void Check(IntPtr h, string name) { if (h == IntPtr.Zero || h == new IntPtr(-1)) ThrowLast(name); }
    private static void ThrowLast(string name) { throw new Win32Exception(Marshal.GetLastWin32Error(), name + " failed"); }
    private static string Quote(string s) { return "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""; }

    private sealed class LaunchRecord { public string Id, CreatedUtc, Image, Status, TaskId, StepId, RunToken; public IntPtr Job, Process; public uint Pid; public int ExitCode; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFO { public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct JOBOBJECT_BASIC_LIMIT_INFORMATION { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION { public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr procAttr, IntPtr threadAttr, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFOEX startup, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);

    public static void Main() { ServiceBase.Run(new AtlasCoordinatorService()); }
}
