#!/usr/bin/env python3
"""Exercise the IPv4 NFQUEUE dataplane in three disposable namespaces.

Requires Linux, root, Python 3.10+, iproute2, nftables, curl and Suricata 8.x
with NFQUEUE support. The kernel must support network namespaces, veth,
bridges and bridge-family nftables queue rules. Exit 77 means unavailable
prerequisites; it never means a successful test.

No physical interfaces, root-namespace nftables rules or sysctls are changed.
This standalone smoke does not validate systemd arming or stalled listeners.
"""

import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime"))
from rule_update_journal import RuleFileJournal, digest
from suricata_commands import SuricataCommands, CommandRejected, process_binding, reload_installed


CLIENT, SERVER, QUEUE = "192.0.2.1", "192.0.2.2", 100
TABLE, SENTINEL, SID = "cs_public0_test", "cs_public0_sentinel", 9100001
SERVER_CODE = r"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ('CS_PUBLIC0_SMOKE_BODY\n' + self.path + '\n').encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
ThreadingHTTPServer(('192.0.2.2', 8080), Handler).serve_forever()
"""


class Unavailable(RuntimeError):
    pass


def run(args, *, data=None, check=True, timeout=15):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=check, timeout=timeout)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def prerequisites():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise Unavailable("Linux and root are required")
    missing = [command for command in ("ip", "nft", "curl", "suricata")
               if not shutil.which(command)]
    if missing:
        raise Unavailable("Missing commands: " + ", ".join(missing))
    version = run(["suricata", "-V"])
    if not re.search(r"\b8\.\d+\.\d+\b", version.stdout + version.stderr):
        raise Unavailable("This smoke requires Suricata 8.x")
    info = run(["suricata", "--build-info"]).stdout
    if not re.search(r"NFQueue support:\s*yes", info, re.IGNORECASE):
        raise Unavailable("Suricata lacks NFQUEUE support")


class Lab:
    def __init__(self, directory):
        self.prefix = "csp0-" + uuid.uuid4().hex[:10] + "-"
        self.names = {role: self.prefix + role for role in ("bridge", "client", "server")}
        self.created, self.processes = [], []
        self.directory, self.logs = Path(directory), []

    def inside(self, role, args, **kwargs):
        return run(["ip", "netns", "exec", self.names[role], *args], **kwargs)

    def spawn(self, role, args, filename):
        output = (self.directory / filename).open("w", encoding="utf-8")
        self.logs.append(output)
        process = subprocess.Popen(["ip", "netns", "exec", self.names[role], *args],
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        self.processes.append(process)
        return process

    def nft(self, text):
        self.inside("bridge", ["nft", "-c", "-f", "-"], data=text)
        self.inside("bridge", ["nft", "-f", "-"], data=text)

    def sentinel(self):
        value = json.loads(self.inside("bridge", ["nft", "-j", "list", "table",
                                                   "bridge", SENTINEL]).stdout)
        return [row for row in value["nftables"] if "metainfo" not in row]

    def http(self, path):
        response = self.inside("client", ["curl", "--silent", "--show-error", "--fail",
            "--noproxy", "*", "--max-time", "2", f"http://{SERVER}:8080{path}"],
            check=False, timeout=5)
        return response.returncode == 0 and response.stdout == "CS_PUBLIC0_SMOKE_BODY\n" + path + "\n"

    def wait(self, predicate, message, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.1)
        raise RuntimeError(message)

    def queue_present(self):
        text = self.inside("bridge", [sys.executable, "-c",
            "from pathlib import Path;p=Path('/proc/net/netfilter/nfnetlink_queue');"
            "print(p.read_text() if p.exists() else '')"]).stdout
        return any(line.split() and line.split()[0] == str(QUEUE) for line in text.splitlines())

    def counters(self):
        table = json.loads(self.inside("bridge", ["nft", "-j", "list", "table", "bridge", TABLE]).stdout)
        return {row["counter"]["name"]: row["counter"]["packets"]
                for row in table["nftables"] if "counter" in row}

    def setup(self):
        # Names are registered for cleanup only after successful creation.
        for role, name in self.names.items():
            try:
                run(["ip", "netns", "add", name])
            except subprocess.CalledProcessError as exc:
                raise Unavailable("Network namespace creation failed: " + exc.stderr.strip()) from exc
            self.created.append(name)
            run(["ip", "-n", name, "link", "set", "lo", "up"])
        try:
            run(["ip", "-n", self.names["bridge"], "link", "add", "br-test", "type", "bridge"])
        except subprocess.CalledProcessError as exc:
            raise Unavailable("Linux bridge unavailable: " + exc.stderr.strip()) from exc
        run(["ip", "-n", self.names["bridge"], "link", "set", "br-test", "up"])
        for role, address in (("client", CLIENT), ("server", SERVER)):
            run(["ip", "-n", self.names["bridge"], "link", "add", role, "type", "veth",
                 "peer", "name", "eth0", "netns", self.names[role]])
            for args in (("link", "set", role, "master", "br-test"), ("link", "set", role, "up")):
                run(["ip", "-n", self.names["bridge"], *args])
            run(["ip", "-n", self.names[role], "addr", "add", address + "/24", "dev", "eth0"])
            run(["ip", "-n", self.names[role], "link", "set", "eth0", "up"])
        self.spawn("server", [sys.executable, "-u", "-c", SERVER_CODE], "http.log")
        self.wait(lambda: self.http("/baseline"), "Baseline HTTP body mismatch")
        try:
            self.nft(f"table bridge {SENTINEL} {{\n counter untouched {{ }}\n}}\n")
            self.nft(f'''table bridge {TABLE} {{
 counter client_queued {{ }}
 counter server_queued {{ }}
 chain forward {{ type filter hook forward priority -240; policy accept;
  meta ibrname "br-test" meta obrname "br-test" iifname "client" ether type ip counter name client_queued queue num {QUEUE} bypass
  meta ibrname "br-test" meta obrname "br-test" iifname "server" ether type ip counter name server_queued queue num {QUEUE} bypass
 }}
}}
''')
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.strip()
            if any(marker in detail.lower() for marker in
                   ("operation not supported", "not permitted", "no such file or directory")):
                raise Unavailable("Kernel nftables/NFQUEUE prerequisite unavailable: " + detail) from exc
            raise
        self.sentinel_before = self.sentinel()
        require(not self.queue_present(), "Queue unexpectedly has a listener")
        require(self.http("/no-listener"), "No-listener bypass failed")

    def configure(self):
        rules = self.directory / "local.rules"
        rules.write_text('alert http any any -> any 8080 (msg:"cs-public0 smoke"; '
            'flow:established,to_server; http.uri; content:"/cs-public0-smoke-"; '
            f'sid:{SID}; rev:1;)\n', encoding="utf-8")
        config = self.directory / "suricata.yaml"
        config.write_text(f'''%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.0.2.0/24]"
    EXTERNAL_NET: "any"
default-log-dir: {json.dumps(str(self.directory))}
default-rule-path: {json.dumps(str(self.directory))}
rule-files: [local.rules]
runmode: workers
max-pending-packets: 64
nfq:
  fail-open: yes
  batchcount: 1
stream:
  inline: yes
  memcap: 32mb
  prealloc-sessions: 64
  drop-invalid: no
  midstream-policy: pass-flow
  memcap-policy: pass-flow
  reassembly:
    memcap: 32mb
    memcap-policy: pass-flow
flow:
  memcap: 16mb
  prealloc: 128
  memcap-policy: pass-packet
defrag:
  memcap: 8mb
  memcap-policy: pass-packet
app-layer:
  error-policy: pass-flow
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
unix-command:
  enabled: yes
  filename: {json.dumps(str(self.directory / 'suricata.socket'))}
stats:
  enabled: yes
  interval: 1
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert]
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
''', encoding="utf-8")
        self.inside("bridge", ["suricata", "-T", "--simulate-ips", "-c", str(config),
            "--init-errors-fatal", "--set", "unix-command.enabled=no"], timeout=40)
        return config

    def exercise(self):
        config = self.configure()
        command_socket = self.directory / "suricata.socket"
        cli_sensor = self.spawn("bridge", ["suricata", "-c", str(config), "-S",
            str(self.directory / "local.rules"), "--init-errors-fatal", "-q", str(QUEUE)],
            "suricata-cli-rule.log")
        self.wait(lambda: cli_sensor.poll() is not None or (self.queue_present() and
            "Engine started" in (self.directory / "suricata-cli-rule.log").read_text()),
            "CLI-rule negative-control sensor did not start")
        require(cli_sensor.poll() is None and command_socket.exists(), "CLI-rule sensor terminated")
        with SuricataCommands(command_socket, process_binding(cli_sensor.pid)) as session:
            require(session.binding["cli_rule_file"], "CLI rule option was not observed")
            try:
                # Deliberate negative command in this disposable lab only.
                session._exchange({"command": "ruleset-reload-rules"}, 3_000_000_000)
            except CommandRejected as exc:
                cli_reload_refusal = exc.response
                require("not possible" in exc.response.get("message", ""), "unexpected reload refusal")
            else:
                raise RuntimeError("CLI-rule sensor unexpectedly accepted reload")
        os.killpg(cli_sensor.pid, signal.SIGTERM)
        cli_sensor.wait(timeout=10)
        require(not self.queue_present(), "CLI-rule listener survived termination")
        if command_socket.exists():
            command_socket.unlink()
        sensor = self.spawn("bridge", ["suricata", "-c", str(config), "--init-errors-fatal",
                                       "-q", str(QUEUE)], "suricata.log")
        self.wait(lambda: sensor.poll() is not None or (self.queue_present() and
            "Engine started" in (self.directory / "suricata.log").read_text()),
            "NFQUEUE listener or Suricata engine did not start")
        require(sensor.poll() is None, "Suricata terminated: " + (self.directory / "suricata.log").read_text())
        before = self.counters()
        marker = "/cs-public0-smoke-" + uuid.uuid4().hex
        require(self.http(marker), "HTTP through live sensor did not return its complete body")
        def correlated_alert(sid=SID, url=marker):
            eve = self.directory / "eve.json"
            for line in eve.read_text().splitlines() if eve.exists() else []:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue  # Last line may still be in progress.
                if (row.get("alert", {}).get("signature_id") == sid
                        and row.get("http", {}).get("url") == url
                        and row.get("src_ip") == CLIENT and row.get("dest_ip") == SERVER
                        and row.get("alert", {}).get("action") == "allowed"):
                    return True
            return False
        self.wait(correlated_alert, "Missing correlated, allowed EVE alert")
        counters = self.counters()
        require(all(counters.get(name, 0) > before.get(name, 0)
                    for name in ("client_queued", "server_queued")),
                "Both traffic directions must reach NFQUEUE")
        rules = self.directory / "local.rules"
        old = rules.read_bytes()
        new = old + ('alert http any any -> any 8080 (msg:"cs-public0 reload"; '
            'flow:established,to_server; http.uri; content:"/cs-public0-reload-"; '
            f'sid:{SID+1}; rev:1;)\n').encode()
        store = self.directory / "journal"
        store.mkdir(mode=0o700)
        journal = RuleFileJournal(self.directory, store)
        transaction = "d" * 64
        journal.prepare(transaction, {rules.name: new}, {rules.name: digest(old)}, {rules.name: digest(new)})
        journal.install(transaction)
        binding = process_binding(sensor.pid)
        with SuricataCommands(command_socket, binding) as session:
            require(not binding["cli_rule_file"], "YAML-rule sensor still uses -S/-s")
            reload_state = reload_installed(journal, transaction, session, 1, 2)
            reload_events = session.events
        require(reload_state["phase"] == "COMMITTED" and not (store / "active.json").exists(),
                "reload transaction did not commit")
        require(sensor.poll() is None and process_binding(sensor.pid) == binding,
                "reload changed sensor process identity")
        reload_marker = "/cs-public0-reload-" + uuid.uuid4().hex
        require(self.http(reload_marker), "HTTP after reload did not return its complete body")
        self.wait(lambda: correlated_alert(SID+1, reload_marker), "New rule did not produce a correlated alert")
        os.killpg(sensor.pid, signal.SIGKILL)
        sensor.wait(timeout=5)
        self.wait(lambda: not self.queue_present(), "NFQUEUE listener survived SIGKILL")
        require(self.http("/after-listener-kill"), "Bypass after listener death failed")
        require(self.sentinel() == self.sentinel_before, "Foreign sentinel table changed")
        self.nft(f"delete table bridge {TABLE}\n")
        require(self.sentinel() == self.sentinel_before, "Cleanup changed foreign sentinel table")
        require(self.http("/after-table-remove"), "HTTP failed after own-table removal")
        return {"result": "PASS", "scope": "isolated-IPv4-dataplane", "alert_sid": SID,
                "direction_counters": counters, "listener_death_bypass": True,
                "cli_rule_reload_refusal": cli_reload_refusal, "reload_new_alert_sid": SID+1,
                "reload_same_process": True, "reload_phase": reload_state["phase"],
                "reload_events": reload_events,
                "foreign_table_preserved": True}

    def cleanup(self):
        errors = []
        for process in reversed(self.processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                errors.append("Child process did not exit")
        for name in reversed(self.created):
            require(name.startswith(self.prefix) and name in self.names.values(), "Refusing foreign namespace")
            result = run(["ip", "netns", "delete", name], check=False)
            if result.returncode:
                errors.append("Namespace cleanup failed: " + result.stderr.strip())
        for output in self.logs:
            output.close()
        require(not errors, "; ".join(errors))


def main():
    lab = None
    try:
        prerequisites()
        def abort(signum, frame):
            raise RuntimeError("Smoke interrupted by signal " + str(signum))
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            signal.signal(signum, abort)
        signal.alarm(120)
        with tempfile.TemporaryDirectory(prefix="cs-public0-netns-") as directory:
            lab = Lab(directory)
            try:
                lab.setup()
                result = lab.exercise()
            finally:
                signal.alarm(0)
                lab.cleanup()
            result["cleanup"] = "complete"
            print(json.dumps(result, sort_keys=True))
        return 0
    except Unavailable as exc:
        print(json.dumps({"result": "SKIP", "reason": str(exc)}))
        return 77
    except Exception as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        print(json.dumps({"result": "FAIL", "reason": detail}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
