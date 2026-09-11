# Accounts present before the competition

An initial baseline records what the agent can observe. It does not establish
that the host or its accounts are trusted. Review the organizer's account list
and the service requirements before approving a baseline or importing protected
identities. Do not automatically protect every account found on the host.

Version 1.9.23 reviews an unknown privileged account even when the account was
already present in the initial baseline or its login is reported disabled.
Linux UID-zero accounts and membership in the known sudo, wheel, and admin
groups are covered, including primary-group membership. This is not a complete
parser of arbitrary sudoers rules, directory privileges, or application-specific
permissions.

The built-in presence exception requires an identifying UID or SID, not just
a familiar spelling. Canonical Linux root has UID zero. Windows Administrator
must have a domain/local account SID ending in RID 500. This follows Microsoft's
[SID documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
Renamed or otherwise unrecognized administrative identities need manifest review.
The exception avoids a presence-only alert; it does not certify the account's
operator or password, and unprotected privileged sessions are analyzed separately.

Accounts with colliding normalized names retain their individual rows and
identifiers. An ambiguous identity does not silently inherit the protected-name
or built-in exception. Changes to an existing protected account's observed UID
or SID raise a protected-identity alert. If identifiers are absent in the old
sample, the detector cannot prove that an identity replacement occurred.

These checks recommend evidence snapshots and identity review. They do not
automatically delete accounts, reset passwords, or terminate service processes.
Session restriction continues to require corroborating behavior, a bound native
process identity, and the applicable action permissions. Protecting a required
scoring account is a preservation decision, not proof that every use is benign.

## What a host agent cannot establish

Someone who already controls root, SYSTEM, or the kernel may alter the agent,
its observations, its files, and local recovery material. Initial malware can
also appear in the first baseline. The defender cannot independently prove that
its own compromised host is clean. Use an organizer-approved account inventory,
known-good configuration and deployment artifacts, and an external trusted
recovery or rebuild path when host trust is lost. The current checks do not
guarantee discovery or removal of every pre-installed backdoor or keylogger.

The regression suite includes accounts present before the first baseline,
noninteractive privileged identities, built-in-name impersonation, name
collisions in both input orders, protected UID/SID replacement, and primary
administrator-group membership. Native fixture results must be reported
separately from these input-based tests.
