#!/usr/bin/env python3
"""Launch one accepted local plan in a separate bounded systemd control group."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from activate_rules import activation_lock, parse_plan, SELF_LIMIT_SECONDS, MIGRATION_LIMIT_SECONDS
from rule_release import absolute, json_bytes, read_path, sha
from rule_update_journal import directory, pin, require, write_file


def launch(path, expected, check_only=False, migration=False):
    require(os.geteuid() == 0 and pin(expected), "root and expected plan SHA256 required")
    path = absolute(str(path))
    require(not str(path).startswith(("/tmp/", "/home/", "/root/")), "persist the plan outside private tmp/home")
    raw = read_path(path, 16384)
    require(sha(raw) == expected, "plan SHA256 differs")
    if migration:
        from migrate_rule_source import parse
        require(not check_only, "migration has its own non-mutating qualification before stopping the sensor")
        plan = parse(raw)
        store = plan["stage"]
        writable = [plan["target"], store, str(Path(plan["before"]["cfg"]["monitor_state"]).parent),
                    "/etc/systemd/system", str(Path(plan["startup_check"]).parent)]
    else:
        plan = parse_plan(raw)
        store = plan["store"]
        writable = [plan["target"], store]
    require(all(repr(p)[1:-1] == p and " " not in p for p in writable), "unsafe sandbox path")
    require(plan["controller_unit"] == "cs-public0-activate-" + plan["nonce"][:16] + ".service",
            "controller unit must derive from the explicit nonce")
    controller = Path(__file__).with_name("migrate_rule_source.py" if migration else "activate_rules.py")
    require(controller.is_file() and not controller.is_symlink(), "missing controller")
    # Claim before a manager call can allocate and lose its reply. No retry.
    with activation_lock(plan["target"]), directory(store, True) as fd:
        write_file(fd, "launch-" + expected + ".json", json_bytes({
            "schema": "cs-public0-launch-v1", "plan_sha256": expected, "unit": plan["controller_unit"],
            "phase": "REQUEST", "check_only": check_only, "migration": migration}))
    lifetime = MIGRATION_LIMIT_SECONDS if migration else SELF_LIMIT_SECONDS
    argv = ["/usr/bin/systemd-run", "--unit=" + plan["controller_unit"], "--service-type=exec",
            "--wait", "--collect", "--pipe", "--property=Restart=no", "--property=CPUQuota=100%",
            "--property=MemoryMax=2G", "--property=MemorySwapMax=0", "--property=TasksMax=32",
            "--property=RuntimeMaxSec=" + str(lifetime), "--property=TimeoutStopSec=10",
            "--property=KillMode=control-group", "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes", "--property=ProtectHome=yes", "--property=ProtectSystem=strict",
            "--property=ReadWritePaths=" + " ".join(dict.fromkeys(writable)),
            "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6"]
    if migration:
        argv += ["--property=ExecStopPost=+/usr/bin/systemctl --no-block start " + plan["monitor_timer"]]
    argv += ["--", sys.executable, str(controller), "--plan", str(path), "--plan-sha256", expected]
    if check_only:
        argv.append("--check-only")
    # The manager owns the hard lifetime; a lost/late launcher reply is unknown.
    result = subprocess.run(argv, timeout=lifetime + 20)
    require(result.returncode == 0, "controller did not complete; inspect its journal, do not retry")
    with directory(store, True) as fd:
        write_file(fd, "launch-" + expected + "-complete.json", json_bytes({
            "schema": "cs-public0-launch-v1", "plan_sha256": expected, "unit": plan["controller_unit"],
            "phase": "MANAGER_EXIT_ZERO", "check_only": check_only, "migration": migration}))
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--migration", action="store_true")
    args = parser.parse_args()
    launch(args.plan, args.plan_sha256, args.check_only, args.migration)


if __name__ == "__main__":
    main()
