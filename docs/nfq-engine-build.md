# Building and auditing the optional NFQUEUE engine

This manually dispatched GitHub Actions workflow produces a Debian package and
text evidence for one exact source commit. It does not install a service, change
a firewall or deploy to a host. The receive-buffer option remains disabled by
default in the Ansible role.

The builder starts from the SHA-256-pinned upstream Suricata 8.0.7 archive. It
applies the GSO/bounded-copy patch followed by the receive-buffer patch, checks
the resulting source bytes, and compiles C and Rust from source. It does not reuse
the historical object cache used during local exploratory qualification.

The package installs only below
/opt/webdisk/suricata-8.0.7-nfq-rcvbuf-v1. It contains the engine, classification
and reference assets, and Suricata's COPYING file. It has no maintainer scripts
or systemd units. Engine modifications are GPL-2.0; see
[the license copy](../patches/COPYING.GPL-2.0). Project automation keeps its
existing repository license.

## Steps

1. Review the exact source commit and run the repository tests.
2. In GitHub Actions, select **Optional NFQUEUE engine**, choose that reviewed
   branch or commit, and run the workflow.
3. Require a successful build and the package audit. Record the workflow run,
   source commit, artifact ID/digest, package SHA-256 and engine SHA-256.
4. Download the artifact from that exact successful run. Do not select an
   unverified file merely because its name or version matches.
5. Independently run the audit command with the recorded pins:

   python3 tools/build_nfq_engine.py audit --package PATH_TO_DEB --package-sha256 PACKAGE_SHA256 --binary-sha256 ENGINE_SHA256

The audit reads the ar/xz/tar containers without invoking package installation.
It rejects unexpected payloads, links, special files, writable/setuid metadata,
duplicate entries, maintainer scripts and mismatching hashes. The metadata binds
the delivered bytes to the reviewed workflow; it is not an author signature.

Before activation, qualify the actual engine on the target kernel and libraries.
Verify the current process, GSO, socket ownership and effective receive buffer.
A configuration test does not exercise NFQUEUE. A live migration must update
the engine path/hash, service, monitor, startup verification and release metadata
together, with a bounded independent rollback. Keep existing rules and loss
history. CI success does not establish throughput, absence of inspection loss,
or a production-readiness decision.

Artifacts are retained for 30 days. Archive an accepted release and its evidence
through your normal release process before that period expires. GitHub's
[artifact documentation](https://docs.github.com/en/actions/tutorials/store-and-share-data)
describes artifact storage and download validation.
