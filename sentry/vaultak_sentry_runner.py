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
    """Monitor a running process using psutil."""
    if not HAS_PSUTIL:
        logger.warning("psutil not installed. Install with: pip install psutil")
        logger.warning("Running without process monitoring.")
        return

    try:
        ps_proc = psutil.Process(proc.pid)
    except psutil.NoSuchProcess:
        return

    seen_connections = set()
    seen_files = set()

    while proc.poll() is None:
        try:
            # Monitor network connections
            try:
                for conn in ps_proc.net_connections(kind="inet"):
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                        if remote not in seen_connections:
                            seen_connections.add(remote)
                            score = 35
                            decision = "ALERT" if score >= alert_threshold else "ALLOW"
                            send_event(api_key, agent_id, session_id, "api_call", remote, score, decision)
                            logger.info(f"[MONITOR] Network: {remote} | Score: {score} | {decision}")
            except (psutil.AccessDenied, AttributeError):
                pass

            # Monitor open files
            try:
                for f in ps_proc.open_files():
                    fpath = f.path
                    if fpath not in seen_files and not fpath.startswith("/proc"):
                        seen_files.add(fpath)
                        # Check blocked resources
                        import fnmatch
                        blocked = any(fnmatch.fnmatch(fpath, p) or p in fpath for p in blocked_resources)
                        score = 70 if blocked else 20
                        decision = "BLOCK" if blocked else ("ALERT" if score >= alert_threshold else "ALLOW")
                        send_event(api_key, agent_id, session_id, "file_read", fpath, score, decision)
                        if blocked:
                            logger.warning(f"[MONITOR] BLOCKED file access: {fpath}")
                            proc.terminate()
                            return
            except (psutil.AccessDenied, AttributeError):
                pass

            # Monitor CPU/memory
            try:
                cpu = ps_proc.cpu_percent(interval=0.1)
                mem = ps_proc.memory_info().rss / 1024 / 1024  # MB
                if cpu > 90:
                    score = 70
                    send_event(api_key, agent_id, session_id, "resource_spike", f"cpu:{cpu:.0f}%", score, "ALERT")
                    logger.warning(f"[MONITOR] High CPU: {cpu:.0f}%")
                if mem > 2048:
                    score = 65
                    send_event(api_key, agent_id, session_id, "resource_spike", f"memory:{mem:.0f}MB", score, "ALERT")
                    logger.warning(f"[MONITOR] High memory: {mem:.0f}MB")
            except (psutil.AccessDenied, AttributeError):
                pass

        except psutil.NoSuchProcess:
            break

        time.sleep(0.5)


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

    # Launch the process
    env = os.environ.copy()
    try:
        proc = subprocess.Popen(
            args.command,
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
