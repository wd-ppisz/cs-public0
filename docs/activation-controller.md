# Manual activation controller

This is a manual day-2 path for a sensor already using one pinned YAML rule
file. It does not poll a feed or automatically roll back an unknown reload.
The separate, explicitly selected migration path below performs one controlled
restart to remove `-S`; ordinary rule activation never restarts the sensor.

Install the seven `runtime/*.py` modules listed by
`ansible/rule-controller.yml` from an accepted commit, supplying their exact
SHA256 values and one explicit target. The default installs code only.
Explicit bootstrap adds a startup check, creates missing gzip/manifest metadata,
and pins immutable files in `release.json`. Existing bytes are verified, never
silently replaced. A code/profile/unit upgrade after bootstrap needs a separately
reviewed migration of those immutable pins. Do not copy new pinned modules over
an active controller or unresolved transaction.

The startup verifier checks the exact rules, complete gzip expansion, counts,
provider manifest and immutable files. Keep the engine binary, effective YAML,
classification/reference/threshold files, startup verifier, unit/drop-in and all
seven controller modules in the immutable map (at most 20 files). The policy is a
root-owned local source pin, not a signature or attestation. All three mutable
rule files and `release.json` must be in the same protected directory.

An activation plan is a bounded, root-owned JSON object with schema
`cs-public0-activation-v1`. Its exact fields are checked by
`activate_rules.parse_plan`:

- `nonce`: a fresh canonical SHA256-format value; the format alone does not
  establish randomness or uniqueness.
- `controller_unit`: `cs-public0-activate-<first16 nonce>.service`.
- `target`, `store`, `candidate`: separate canonical protected directories.
- `candidate_rules`, `candidate_gzip`, their exact SHA256 values, and
  `expected_old`: SHA256 of all four current assets.
- `cfg`: service, queue, table, bridge, chain, priority, socket, binary, effective YAML, rules path and
  monitor-state path. `binding` is a fresh `process_binding(MainPID)`;
  `unit` contains MainPID, InvocationID, ControlGroup, ActiveState and SubState.
- `selector_sha256`: `selector_hash(nft JSON)`, retaining handles and the full
  selector while excluding only current named-counter packet/byte values.
- `qualification_settings`: the exact active classification/reference/threshold
  and `stream.inline=yes` overrides. Each support file must be immutable.
- `startup_check`: optional pinned provider verifier path, invoked with the
  single argument `verify`. The release verifier always runs independently.

The live command line must select the same binary, YAML and NFQUEUE as the
plan. Only `-c`, `-q`, `-l`, the workers run mode, fatal initialization checks,
the declared qualification overrides and the small capture/statistics/socket
override allowlist in `effective_settings` are supported. Hidden rule-file,
variable, include or other overrides are refused; checking a YAML dump alone
does not establish what a process started with additional CLI overrides loads.

Persist the plan outside private temporary/home directories, then launch:

```sh
sudo python3 /usr/local/libexec/cs-public0-update/run_rule_activation.py \
  --plan /var/lib/cs-public0/requests/accepted-plan.json \
  --plan-sha256 EXACT_PLAN_SHA256 --check-only
```

Check-only qualifies the candidate without replacing installed assets or
reloading. For activation, prepare a **new nonce and reviewed plan** and omit
`--check-only`. Every request/launch is single-use; a lost manager reply is
unknown and must not be retried. Inspect the existing unit and journal first.

The launcher requests CPUQuota=100%, MemoryMax=2G, swap=0, TasksMax=32,
RuntimeMaxSec=240, TimeoutStopSec=10 and KillMode=control-group. The child checks
its actual MainPID/InvocationID, effective cgroup limits and manager properties.
These are engineering bounds, not reserved capacity or a measured protection
budget. The running sensor has a separate resource envelope; reload may retain
old and new detection engines concurrently.

The controller holds the update lock, verifies sources/unit/process/NFQUEUE/
selector and fresh unlatched monitoring, compiles an exclusive candidate
snapshot with `-T --simulate-ips`, and retains its bounded original stdout.
The qualification-only `-S candidate.rules` deliberately selects the snapshot;
the live process must not have `-S/-s`. No NFQUEUE capture starts during this
engine test. The 1 MiB log cap and 120-second child timeout sit inside the
controller's systemd bounds.

It then journals four complete images: rules, gzip, provider manifest and
release policy. The startup checks must pass after installation. Reload intent
is durable before the one blocking command. `COMMITTED` records the existing
command/file receipt; only fresh post-reload monitoring, the same process and
NFQUEUE socket, counter/sequence progress and exact installed bytes yield the
separate `ACTIVATED` result.

Failure before reload can leave a prepared/installed set for explicit recovery.
Failure after intent remains `RELOAD_PENDING`, without automatic retry or
restore. A post-reload health failure may leave command `COMMITTED` but never
an `ACTIVATED` receipt. Preserve all request, qualification and journal files.
Neither this controller nor a green monitor proves complete packet inspection,
service/OSD p99 or G6 qualification.

## Disposable VM qualification

`tests/integration/activation.py` is a separate, alert-only systemd/NFQUEUE
qualification executable for the disposable GitHub Actions VM. It uses the
real controller, a real sensor and the real monitor in private namespaces. It
installs all four release images and requires a correlated alert from the new
rule, legal request completion, an `ACTIVATED` receipt and the same sensor
process/socket. Root-owned byte copies keep the immutable source contract
independent of the runner checkout's user ownership.

Four additional filesystem fixtures stop and actually kill a child after
durable preparation, the first completed replacement, complete installation
and reload intent. The first three explicitly recover every original image;
the unknown reload case must refuse restore/reinstall and retain its intent.
Those fixtures send no engine command and do not qualify production rollback.
The VM is the hard outer cleanup boundary. This executable refuses ordinary
non-CI invocation and must never be run on a production host. A missing
prerequisite fails the CI gate; SKIP is not acceptance.
The harness allows 420 seconds for setup, the bounded controller and fault
fixtures; the entire dataplane job expires after 15 minutes, including setup.
Sensor and monitor units have a separate 600-second lifetime; the controller
retains its required 240-second limit. Legal traffic runs until controller
completion or a 300-second cap, covering the controller wait of 260 seconds.

This small two-rule laboratory contract does not qualify a full provider feed,
production resource headroom, service/OSD p99, or fleet rollout. Keep those
acceptances separate from a successful CI run and production activation.

## Existing CLI-selected rule sources

An existing sensor started with `-S` requires a separate migration plan with
schema `cs-public0-yaml-migration-v1`, validated by `migrate_rule_source.parse`.
Prepare four exact old/new asset pins: YAML, provider manifest, sensor unit and
provider startup verifier. The unit transition may only remove the exact
`-S /absolute/production.rules` pair. The provider manifest may only change its
YAML pin. The rules and gzip remain byte-identical. The new verifier must
delegate to the complete immutable release policy on every sensor start.

The root-owned private `stage` must share the monitor-state filesystem and be
separate from the rule directory. It contains the four accepted `.new` images
and the immutable plan. Bind `before` to a fresh unit/process/NFQUEUE/nft
context and the exact active qualification overrides. Include every new
startup asset and support file in the new immutable map. Keep the passive
sensor inactive and disabled.

The provider must check every additional static pin required by its startup
verifier before launching migration. For example, a verifier that also checks
a package and threshold file must require their exact pins in the plan;
generic engine/YAML checks alone do not establish that provider contract.

Launch with the same single-use launcher and `--migration`, without
`--check-only`. The migrator first compiles the new YAML without `-S`, preserving
the bounded original qualification output. It then pauses the monitor timer,
locks its state, stops the inline sensor and renames the original monitor JSON
into `monitor-state.before.json`. The old epoch is retained verbatim with its
SHA256 and four original asset images. An unresolved latch/history blocks the
migration before stopping the sensor.

Immediately before `STOP_REQUEST`, the migrator also requires at least 195
seconds of its separate 360-second migration lifetime to remain: the stop/start command limits,
timer restoration, post-start observation and ten seconds for bookkeeping.
Time spent in qualification and stopping the monitor consumes this budget.
A slow preparation aborts while the original sensor and epoch remain intact,
then attempts to restore the monitor timer. The guard is conservative local
accounting; the separate systemd lifetime remains the hard outer bound.

Migration uses `RuntimeMaxSec=360` (and a 380-second launcher wait), while a
normal activation keeps its 240-second limit. YAML qualification has a
120-second child timeout. The 1-CPU/2-GiB/32-task envelope and 10-second stop
limit are the same in both modes. Choose these engineering time bounds using
actual compilation measurements at the declared CPU quota; a measurement at
50% CPU cannot be directly treated as a 1-CPU compilation duration. The guard
still refuses to stop the sensor when preparation leaves less than 195 seconds.

After installing and verifying the four new images, the migrator initializes
the coherent release policy, verifies startup, reloads systemd's unit definition
and starts a new inline instance. It requires YAML selection, a new invocation,
NFQUEUE mode, unchanged rules, the exact new selector and fresh monitoring.
`MIGRATED` is emitted only after those checks. The launcher installs an
`ExecStopPost` action to start the monitor timer even after controller SIGKILL;
the normal failure path also attempts timer restoration before propagating the
error. Neither path activates the passive sensor or restores old files.

The restart temporarily removes the managed queue selector according to the
provider unit's existing stop/start policy. Assess that operational window
before launch. A lost reply, partial file install or failed start requires
inspection of the retained phase and assets, not a repeated request or an
automatic rollback. Unit tests with mocked manager/sensor ports do not qualify
this restart on a real host; record that deployment and its readback separately.
