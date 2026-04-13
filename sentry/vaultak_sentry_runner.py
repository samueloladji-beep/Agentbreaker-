#!/usr/bin/env python3
"""
Vaultak Sentry process runner.
Usage: vaultak-sentry run [options] command [args...]

Example:
    vaultak-sentry run python my_agent.py
    vaultak-sentry run --name my-agent --pause-threshold 60 node agent.js
"""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from datetime import datetime

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Sentry] %(message)s")
logger = logging.getLogger("vaultak-sentry")

API_ENDPOINT = os.environ.get("VAULTAK_API_ENDPOINT", "https://vaultak.com")


def get_api_key():
    key = os.environ.get("VAULTAK_API_KEY", "")
    if not key:
        config_path = os.path.expanduser("~/.vaultak/config.json")
        if os.path.exists(config_path):
            with open(config_path) as f:
                key = json.load(f).get("api_key", "")
    return key


def send_event(api_key, agent_id, session_id, action_type, resource, score, decision):
    data = json.dumps({
        "agent_id": agent_id,
        "session_id": session_id,
        "action_type": action_type,
        "resource": resource,
        "risk_score": score / 100.0,
        "decision": decision,
        "timestamp": datetime.utcnow().isoformat(),
        "source": "sentry",
    }).encode("utf-8")
    def _post():
        try:
            req = urllib.request.Request(
                f"{API_ENDPOINT}/api/actions",
                data=data,
                headers={"Content-Type": "application/json", "x-api-key": api_key},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass
    threading.Thread(target=_post, daemon=True).start()


def monitor_process(proc, agent_id, session_id, api_key, pause_threshold, rollback_threshold, alert_threshold, blocked_resources):
    """Monitor a running process using psutil + watchdog filesystem events."""
    if not HAS_PSUTIL:
        logger.warning("psutil not installed. Install with: pip install psutil")
        logger.warning("Running without process monitoring.")
        return

    try:
        ps_proc = psutil.Process(proc.pid)
    except psutil.NoSuchProcess:
        return

    seen_connections = set()
    file_snapshots = {}
    import fnmatch

    # ── Watchdog filesystem monitoring ───────────────────────────────────
    watchdog_observer = None
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class AgentFileHandler(FileSystemEventHandler):
            def on_modified(self, event):
                if event.is_directory:
                    return
                fpath = event.src_path
                blocked = any(fnmatch.fnmatch(fpath, p) or p.strip("*") in fpath
                              for p in blocked_resources)
                score = 75 if blocked else 40
                decision = "BLOCK" if blocked else ("ALERT" if score >= alert_threshold else "ALLOW")
                send_event(api_key, agent_id, session_id, "file_write", fpath, score, decision)
                logger.info(f"[SENTRY] File modified: {fpath} | {decision}")
                if blocked:
                    logger.warning(f"[SENTRY] BLOCKED - terminating agent")
                    proc.terminate()

            def on_created(self, event):
                if event.is_directory:
                    return
                fpath = event.src_path
                # Save snapshot for rollback
                try:
                    with open(fpath, "rb") as f:
                        file_snapshots[fpath] = None  # new file - rollback = delete
                except Exception:
                    pass
                blocked = any(fnmatch.fnmatch(fpath, p) or p.strip("*") in fpath
                              for p in blocked_resources)
                score = 60 if blocked else 30
                decision = "BLOCK" if blocked else ("ALERT" if score >= alert_threshold else "ALLOW")
                send_event(api_key, agent_id, session_id, "file_write", fpath, score, decision)
                logger.info(f"[SENTRY] File created: {fpath} | {decision}")

            def on_deleted(self, event):
                if event.is_directory:
                    return
                fpath = event.src_path
                score = 80
                decision = "ALERT" if score >= alert_threshold else "ALLOW"
                send_event(api_key, agent_id, session_id, "delete", fpath, score, decision)
                logger.warning(f"[SENTRY] File deleted: {fpath} | {decision}")

        handler = AgentFileHandler()
        watchdog_observer = Observer()
        # Watch /tmp and current working directory only (not entire home)
        import os as _os
        watch_dirs = ["/tmp", _os.getcwd()]
        # Add any directories from blocked resources
        for pattern in blocked_resources:
            parent = _os.path.dirname(pattern.strip("*"))
            if parent and _os.path.exists(parent):
                watch_dirs.append(parent)
        seen_dirs = set()
        for watch_dir in watch_dirs:
            if watch_dir and _os.path.exists(watch_dir) and watch_dir not in seen_dirs:
                watchdog_observer.schedule(handler, watch_dir, recursive=True)
                seen_dirs.add(watch_dir)
                logger.info(f"[SENTRY] Watching: {watch_dir}")
        watchdog_observer.start()
        logger.info("[SENTRY] Filesystem watcher active")
    except ImportError:
        logger.warning("[SENTRY] watchdog not installed - filesystem events limited")
        logger.warning("Install with: pip install watchdog")

    # ── Network + process monitoring loop ────────────────────────────────
    while proc.poll() is None:
        try:
            # Monitor network connections - real time
            try:
                for conn in ps_proc.net_connections(kind="inet"):
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                        if remote not in seen_connections:
                            seen_connections.add(remote)
                            # Score based on destination
                            sensitive = any(kw in remote for kw in ["openai", "anthropic", "api"])
                            score = 45 if sensitive else 30
                            decision = "ALERT" if score >= alert_threshold else "ALLOW"
                            send_event(api_key, agent_id, session_id, "api_call", remote, score, decision)
                            logger.info(f"[SENTRY] Network: {remote} | Score: {score} | {decision}")
            except (psutil.AccessDenied, AttributeError):
                pass

            # Monitor CPU/memory
            try:
                cpu = ps_proc.cpu_percent(interval=None)
                mem = ps_proc.memory_info().rss / 1024 / 1024
                if cpu > 90:
                    send_event(api_key, agent_id, session_id, "resource_spike", f"cpu:{cpu:.0f}%", 70, "ALERT")
                    logger.warning(f"[SENTRY] High CPU: {cpu:.0f}%")
                if mem > 2048:
                    send_event(api_key, agent_id, session_id, "resource_spike", f"memory:{mem:.0f}MB", 65, "ALERT")
                    logger.warning(f"[SENTRY] High memory: {mem:.0f}MB")
            except (psutil.AccessDenied, AttributeError):
                pass

            # Monitor child processes
            try:
                for child in ps_proc.children(recursive=True):
                    cmd = " ".join(child.cmdline()) if child.cmdline() else str(child.pid)
                    blocked = any(p.strip("*") in cmd for p in blocked_resources)
                    score = 65 if blocked else 40
                    decision = "BLOCK" if blocked else ("ALERT" if score >= alert_threshold else "ALLOW")
                    if blocked:
                        send_event(api_key, agent_id, session_id, "execute", cmd[:100], score, decision)
                        logger.warning(f"[SENTRY] Blocked subprocess: {cmd[:100]}")
                        child.terminate()
            except (psutil.AccessDenied, AttributeError):
                pass

        except psutil.NoSuchProcess:
            break

        time.sleep(0.1)  # 100ms polling - much faster than before

    # Stop watchdog
    if watchdog_observer:
        watchdog_observer.stop()
        watchdog_observer.join()



def inject_vaultak(command, env, api_key, agent_id, alert_threshold,
                   pause_threshold, rollback_threshold, blocked_resources):
    """
    Detect the language of the agent process and inject Vaultak SDK
    automatically — zero code changes required.
    Returns (command, env) tuple.
    """
    if not command:
        return command, env
    command = list(command)  # make a mutable copy

    cmd = command[0].lower()
    cmd_base = os.path.basename(cmd)

    # Set common env vars for all languages
    env["VAULTAK_API_KEY"] = api_key
    env["VAULTAK_AGENT_ID"] = agent_id
    env["VAULTAK_ALERT_THRESHOLD"] = str(alert_threshold)
    env["VAULTAK_PAUSE_THRESHOLD"] = str(pause_threshold)
    env["VAULTAK_ROLLBACK_THRESHOLD"] = str(rollback_threshold)
    if blocked_resources:
        env["VAULTAK_BLOCKED"] = ",".join(blocked_resources)

    # ── Python injection ─────────────────────────────────────────────────
    if any(p in cmd_base for p in ["python", "python3", "python2"]):
        injector_path = _get_python_injector()
        if injector_path:
            # Most reliable method: use -c to preload injector then exec the script
            # Transform: python3 script.py args
            # Into:      python3 -c "exec(open('injector').read()); exec(open('script.py').read())"
            # For -c commands, wrap with injector prefix
            if len(command) >= 2:
                if command[1] == '-c' and len(command) >= 3:
                    # python3 -c "code" -> python3 -c "injector_code; original_code"
                    original_code = command[2]
                    inject_code = f"exec(open(r'{injector_path}').read())\n"
                    command[2] = inject_code + original_code
                elif command[1] == '-m' and len(command) >= 3:
                    # python3 -m module -> prepend injector via PYTHONPATH
                    injector_dir = os.path.dirname(injector_path)
                    existing = env.get("PYTHONPATH", "")
                    env["PYTHONPATH"] = injector_dir + (":" + existing if existing else "")
                else:
                    # python3 script.py -> python3 -c "inject(); exec(script)"
                    script = command[1]
                    rest = command[2:]
                    inject_code = f"exec(open(r'{injector_path}').read())\nimport sys; sys.argv={[script]+rest}\nexec(open(r'{script}').read())"
                    command[1] = '-c'
                    command[2:] = [inject_code]
            logger.info(f"[INJECT] Python SDK injected via command wrapping")
        else:
            logger.warning("[INJECT] Python injector not found — install vaultak: pip install vaultak")

    # ── Node.js injection ────────────────────────────────────────────────
    elif any(p in cmd_base for p in ["node", "nodejs"]):
        injector_path = _get_node_injector()
        if injector_path:
            existing = env.get("NODE_OPTIONS", "")
            env["NODE_OPTIONS"] = f"--require {injector_path}" + (" " + existing if existing else "")
            logger.info(f"[INJECT] Node.js SDK injected via NODE_OPTIONS")
        else:
            logger.warning("[INJECT] Node.js injector not found — install vaultak: npm install -g vaultak")

    # ── Ruby injection ───────────────────────────────────────────────────
    elif any(p in cmd_base for p in ["ruby", "ruby3", "ruby2", "ruby4"]):
        injector_path = _get_ruby_injector()
        if injector_path:
            existing = env.get("RUBYOPT", "")
            env["RUBYOPT"] = f"-r {injector_path}" + (" " + existing if existing else "")
            # Use Homebrew Ruby if available (has vaultak gem)
            homebrew_ruby = "/opt/homebrew/opt/ruby/bin/ruby"
            import os as _os
            if _os.path.exists(homebrew_ruby) and cmd_base in ["ruby"]:
                command[0] = homebrew_ruby
                logger.info(f"[INJECT] Using Homebrew Ruby with vaultak gem")
            env["GEM_PATH"] = "/opt/homebrew/lib/ruby/gems/4.0.0:/opt/homebrew/Cellar/ruby/4.0.2/lib/ruby/gems/4.0.0"
            logger.info(f"[INJECT] Ruby SDK injected via RUBYOPT")
        else:
            logger.warning("[INJECT] Ruby injector not available yet")

    # ── Java injection ───────────────────────────────────────────────────
    elif any(p in cmd_base for p in ["java"]):
        logger.info("[INJECT] Java detected — network/filesystem monitoring active via Sentry")
        logger.info("[INJECT] For full SDK injection, use the Vaultak Java agent (coming soon)")

    # ── Go injection ─────────────────────────────────────────────────────
    elif any(p in cmd_base for p in ["go"]):
        logger.info("[INJECT] Go binary detected — network/filesystem monitoring active via Sentry")
        logger.info("[INJECT] For full SDK support, use github.com/vaultak/vaultak-go (coming soon)")

    else:
        logger.info(f"[INJECT] Language not detected for '{cmd_base}' — Sentry monitoring active")

    return command, env


def _get_python_injector():
    """Write and return path to the Python SDK injector."""
    import tempfile
    inject_dir = os.path.join(tempfile.gettempdir(), "vaultak_inject_py")
    os.makedirs(inject_dir, exist_ok=True)
    sitecustomize = os.path.join(inject_dir, "sitecustomize.py")

    code = """
import os, sys

if not hasattr(sys, '_vaultak_injected'):
    sys._vaultak_injected = True
    for _p in [os.path.expanduser("~/vaultak"), "/Users/samueloladji/vaultak"]:
        if os.path.exists(_p) and _p not in sys.path:
            sys.path.insert(0, _p)
    api_key = os.environ.get("VAULTAK_API_KEY", "")
    agent_id = os.environ.get("VAULTAK_AGENT_ID", "default")
    alert_threshold = int(os.environ.get("VAULTAK_ALERT_THRESHOLD", "30"))
    pause_threshold = int(os.environ.get("VAULTAK_PAUSE_THRESHOLD", "60"))
    rollback_threshold = int(os.environ.get("VAULTAK_ROLLBACK_THRESHOLD", "85"))
    blocked = [b for b in os.environ.get("VAULTAK_BLOCKED", "").split(",") if b]
    if api_key:
        try:
            from vaultak.interceptor import install_all, uninstall_all
            from vaultak.core import VaultakMonitor
            monitor = VaultakMonitor(
                agent_id=agent_id,
                api_key=api_key,
                api_endpoint=os.environ.get("VAULTAK_API_ENDPOINT", "https://vaultak.com"),
                alert_threshold=alert_threshold,
                pause_threshold=pause_threshold,
                rollback_threshold=rollback_threshold,
                allowed_resources=None,
                blocked_resources=blocked,
                max_actions_per_minute=60,
            )
            install_all(monitor)
            import atexit
            atexit.register(uninstall_all)
            print(f"[Vaultak] Python agent monitoring active: {agent_id}", file=sys.stderr)
        except Exception:
            pass
"""
    with open(sitecustomize, "w") as f:
        f.write(code)
    return sitecustomize


def _get_node_injector():
    """Find or create the Node.js injector file."""
    # Check if vaultak npm package is installed globally
    import shutil
    node_modules_paths = [
        os.path.join(os.path.expanduser("~"), ".npm-global", "lib", "node_modules", "vaultak", "vaultak-injector.js"),
        "/usr/local/lib/node_modules/vaultak/vaultak-injector.js",
        "/usr/lib/node_modules/vaultak/vaultak-injector.js",
        os.path.join(os.path.expanduser("~"), "vaultak", "sdk-node", "vaultak-injector.js"),
    ]
    for p in node_modules_paths:
        if os.path.exists(p):
            return p

    # Write a standalone injector to temp
    import tempfile
    inject_dir = os.path.join(tempfile.gettempdir(), "vaultak_inject_node")
    os.makedirs(inject_dir, exist_ok=True)
    injector = os.path.join(inject_dir, "vaultak-injector.js")

    code = """
'use strict';
const apiKey = process.env.VAULTAK_API_KEY || '';
const agentId = process.env.VAULTAK_AGENT_ID || 'node-agent';
if (apiKey) {
    try {
        const vaultakPath = require.resolve('vaultak');
        const { Vaultak } = require(vaultakPath);
        const vt = new Vaultak({
            apiKey,
            agentId,
            alertThreshold: parseInt(process.env.VAULTAK_ALERT_THRESHOLD || '30'),
            pauseThreshold: parseInt(process.env.VAULTAK_PAUSE_THRESHOLD || '60'),
            rollbackThreshold: parseInt(process.env.VAULTAK_ROLLBACK_THRESHOLD || '85'),
            blockedResources: (process.env.VAULTAK_BLOCKED || '').split(',').filter(Boolean),
        });
        vt.monitor(agentId);
        console.error('[Vaultak] Node.js agent monitoring active: ' + agentId);
    } catch(e) {
        console.error('[Vaultak] Could not load SDK: ' + e.message);
        console.error('[Vaultak] Install with: npm install vaultak');
    }
}
"""
    with open(injector, "w") as f:
        f.write(code)
    return injector


def _get_ruby_injector():
    """Create a Ruby injector file with full SDK support."""
    import tempfile
    inject_dir = os.path.join(tempfile.gettempdir(), "vaultak_inject_ruby")
    os.makedirs(inject_dir, exist_ok=True)
    injector = os.path.join(inject_dir, "vaultak_injector.rb")
    code = """
# Vaultak Ruby injector - auto-loaded via RUBYOPT
# Guard against double execution
unless defined?($vaultak_injected)
  $vaultak_injected = true

  api_key = ENV['VAULTAK_API_KEY'] || ''
  agent_id = ENV['VAULTAK_AGENT_ID'] || 'ruby-agent'
  alert_threshold = (ENV['VAULTAK_ALERT_THRESHOLD'] || '30').to_i
  pause_threshold = (ENV['VAULTAK_PAUSE_THRESHOLD'] || '60').to_i
  rollback_threshold = (ENV['VAULTAK_ROLLBACK_THRESHOLD'] || '85').to_i
  blocked = (ENV['VAULTAK_BLOCKED'] || '').split(',').reject(&:empty?)

  if !api_key.empty?
    begin
      require 'vaultak'
      $vaultak_client = Vaultak::Client.new(
        api_key: api_key,
        agent_id: agent_id,
        alert_threshold: alert_threshold,
        pause_threshold: pause_threshold,
        rollback_threshold: rollback_threshold,
        blocked_resources: blocked
      )

      # Patch File.write globally
      orig_write = File.method(:write)
      File.define_singleton_method(:write) do |path, *args|
        $vaultak_client.snapshot_file(path.to_s)
        decision = $vaultak_client.intercept('file_write', path.to_s, {})
        raise Vaultak::VaultakBlockError, "File write blocked: #{path}" if decision == 'BLOCK'
        orig_write.call(path, *args)
      end

      # Patch File.delete globally
      orig_delete = File.method(:delete)
      File.define_singleton_method(:delete) do |*paths|
        paths.each do |path|
          decision = $vaultak_client.intercept('delete', path.to_s, {})
          raise Vaultak::VaultakBlockError, "File delete blocked: #{path}" if decision == 'BLOCK'
        end
        orig_delete.call(*paths)
      end

      at_exit do
        # Restore originals on exit
        if orig_write
          File.define_singleton_method(:write) { |*args| orig_write.call(*args) }
        end
        if orig_delete
          File.define_singleton_method(:delete) { |*args| orig_delete.call(*args) }
        end
      end

      $stderr.puts "[Vaultak] Ruby agent monitoring active: #{agent_id}"
    rescue LoadError
      $stderr.puts "[Vaultak] Could not load SDK. Install with: gem install vaultak"
    rescue => e
      $stderr.puts "[Vaultak] Injection error: #{e.message}"
    end
  end
end
"""
    with open(injector, "w") as f:
        f.write(code)
    return injector


def cmd_run(args):
    api_key = get_api_key()
    if not api_key and not args.no_auth:
        print("No API key found. Set VAULTAK_API_KEY or run: vaultak-sentry auth --api-key vtk_...")
        sys.exit(1)

    agent_id = args.name or args.command[0]
    session_id = str(uuid.uuid4())
    blocked = args.block or []

    logger.info(f"Starting agent: {' '.join(args.command)}")
    logger.info(f"Agent ID: {agent_id} | Session: {session_id[:8]}...")
    logger.info(f"Thresholds: Alert={args.alert_threshold} Pause={args.pause_threshold} Rollback={args.rollback_threshold}")

    # Send session start event
    send_event(api_key, agent_id, session_id, "session_start", "sentry", 0, "ALLOW")

    # Detect language and inject Vaultak SDK
    env = os.environ.copy()
    injected_command, env = inject_vaultak(args.command, env, api_key, agent_id,
                         args.alert_threshold, args.pause_threshold,
                         args.rollback_threshold, blocked)

    logger.info(f"[DEBUG] Final command: {injected_command[:3] if len(injected_command) > 3 else injected_command}")
    try:
        proc = subprocess.Popen(
            injected_command,
            env=env,
            stdout=None,
            stderr=None,
        )
    except FileNotFoundError:
        logger.error(f"Command not found: {args.command[0]}")
        sys.exit(1)

    logger.info(f"Process started: PID {proc.pid}")

    # Start monitoring in background thread
    monitor_thread = threading.Thread(
        target=monitor_process,
        args=(proc, agent_id, session_id, api_key,
              args.pause_threshold, args.rollback_threshold,
              args.alert_threshold, blocked),
        daemon=True
    )
    monitor_thread.start()

    # Handle Ctrl+C
    def handle_interrupt(sig, frame):
        logger.info("Interrupted — stopping agent...")
        proc.terminate()
        send_event(api_key, agent_id, session_id, "session_end", "interrupted", 0, "ALLOW")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)

    # Wait for process to finish
    exit_code = proc.wait()
    send_event(api_key, agent_id, session_id, "session_end", f"exit:{exit_code}", 0, "ALLOW")
    logger.info(f"Agent finished with exit code: {exit_code}")
    return exit_code


def cmd_auth(args):
    config_dir = os.path.expanduser("~/.vaultak")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config.json")
    with open(config_path, "w") as f:
        json.dump({"api_key": args.api_key}, f)
    os.chmod(config_path, 0o600)
    print(f"API key saved to {config_path}")


def cmd_status(args):
    api_key = get_api_key()
    print(f"API key: {'configured' if api_key else 'NOT configured'}")
    print(f"API endpoint: {API_ENDPOINT}")
    print(f"psutil: {'installed' if HAS_PSUTIL else 'NOT installed (run: pip install psutil)'}")


def main():
    parser = argparse.ArgumentParser(
        prog="vaultak-sentry",
        description="Vaultak Sentry — monitor any AI agent with zero code changes"
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # run command
    run_parser = subparsers.add_parser("run", help="Run and monitor an agent process")
    run_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")
    run_parser.add_argument("--name", help="Agent name (default: command name)")
    run_parser.add_argument("--alert-threshold", type=int, default=30)
    run_parser.add_argument("--pause-threshold", type=int, default=60)
    run_parser.add_argument("--rollback-threshold", type=int, default=85)
    run_parser.add_argument("--block", nargs="+", help="Resource patterns to block")
    run_parser.add_argument("--no-auth", action="store_true", help="Run without authentication")

    # auth command
    auth_parser = subparsers.add_parser("auth", help="Save API key")
    auth_parser.add_argument("--api-key", required=True)

    # status command
    subparsers.add_parser("status", help="Check Sentry status")

    args = parser.parse_args()

    if args.subcommand == "run":
        sys.exit(cmd_run(args))
    elif args.subcommand == "auth":
        cmd_auth(args)
    elif args.subcommand == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
