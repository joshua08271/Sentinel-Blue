# Sentinel Blue 1.9.45 defensive validation

The 1.9.43 Azure Windows setup attempt spent 61.931 seconds in two unsuccessful
feature-query attempts. A controlled regression also showed that restarting a
query after 30 seconds prevented a 45-second read from completing, despite an
existing 60-second total allowance.

Version 1.9.45 lets the compiler-owned Windows feature query use that allowance
continuously. One retry is still possible after an early uncertain return, but
it receives only the unused portion of the same allowance and caller deadline.
Late native results are explicitly uncertain and cannot authorize provisioning.
Runbooks retain their 30-second native-check allowance. The overall setup goal,
mutation replay safeguards, 75-second collection budget and recovery gates are
unchanged.

The focused setup suite passes all 40 tests, including slow continuous work,
early retry, total budget and late-success holds. Full 1.9.45 CI and native Azure
Windows verification are pending. This change is a candidate improvement to the
feature-query failure, not a claim that Windows load performance is solved.

The preceding public versions passed their Linux and selected native Windows CI.
The 1.9.43 Azure Linux guest passed all seven defensive phases, while Windows
failed setup, healthy HTTP timing, collection responsiveness and loaded inventory.
The Windows service repair and controller continuity phases passed. All four VMs
were deallocated, the original network restored and private staging removed.
The subsequent 1.9.44 Linux retest is recorded separately when final evidence is
available. Current and historical measurements must remain tied to their exact
runtime hashes.

Only owned defensive fixtures, ordinary faults, finite CPU load and bounded
loopback delays are tested. No live red-team campaign, full-event availability,
VM reboot continuity or external competition scorer result is claimed.
