"""Command line interface for all Sentinel Blue components."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sentinel-blue")
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = root.add_subparsers(dest="command", required=True)

    controller = subcommands.add_parser("controller", help="run the controller and dashboard")
    controller.add_argument("--bind", default="127.0.0.1")
    controller.add_argument("--port", type=int, default=8765)
    controller_token = controller.add_mutually_exclusive_group(required=True)
    controller_token.add_argument("--token")
    controller_token.add_argument("--token-file")
    controller.add_argument("--database", default="sentinel-blue.db")
    controller.add_argument(
        "--event-profile", required=True,
        help="private approved default-deny event profile/inventory JSON",
    )
    controller.add_argument(
        "--range-deployment",
        action="store_true",
        help=(
            "explicitly permit a checksum-pinned disposable range profile; "
            "never valid for a live competition profile"
        ),
    )
    controller.add_argument(
        "--model",
        help="external risk model; requires an exact release.model_sha256 profile binding",
    )
    controller.add_argument(
        "--adaptive-model-output",
        help="train a regression-gated candidate model when the controller stops",
    )
    controller.add_argument(
        "--campaign-id",
        help="bounded evidence/training campaign identifier; generated once per database if omitted",
    )
    controller.add_argument(
        "--authorized-network",
        action="append",
        default=[],
        help="authorized CIDR for passive topology filtering; repeat as needed",
    )
    controller.add_argument("--probe-config", help="JSON file containing relay-side service probes")
    controller.add_argument("--probe-interval", type=float, default=15.0)
    controller.add_argument(
        "--enrollment-window",
        type=float,
        default=3600.0,
        help="seconds after startup in which new agents may enroll",
    )
    controller.add_argument("--max-agents", type=int, default=512)
    controller.add_argument("--stale-after", type=float, default=90.0)
    controller.add_argument("--maintenance-interval", type=float, default=30.0)
    controller.add_argument("--retention-days", type=int, default=30)
    controller.add_argument(
        "--backup-directory",
        help="existing private directory for authenticated recovery bundles",
    )
    controller.add_argument("--backup-interval", type=float, default=900.0)
    controller.add_argument(
        "--backup-keep", type=int, default=96,
        help="maximum authenticated controller bundles to retain (minimum: 2)",
    )
    controller.add_argument(
        "--recovery-key-file",
        required=True,
        help="private raw recovery signing key; never copied into a backup",
    )
    controller.add_argument(
        "--recovery-anchor",
        required=True,
        help="protected signed recovery anchor stored outside backup bundles",
    )
    operator_token = controller.add_mutually_exclusive_group(required=True)
    operator_token.add_argument(
        "--operator-token",
        help="independent operator secret; prefer --operator-token-file",
    )
    operator_token.add_argument(
        "--operator-token-file",
        help="existing private file containing an independent operator secret",
    )
    controller.add_argument(
        "--operator-principal-id",
        required=True,
        help="bounded blue-team identity recorded for every signed operator request",
    )
    controller.add_argument(
        "--operator-credential-epoch",
        type=int,
        default=2,
        help=(
            "operator key epoch; increment by exactly one with every key rotation "
            "(authenticated-recovery deployments begin at 2)"
        ),
    )
    controller.add_argument(
        "--auto-restore",
        action="store_true",
        help="automatically queue approved integrity restoration when no change grant is active",
    )
    controller.add_argument(
        "--restore-confirmations",
        type=int,
        default=2,
        choices=range(1, 6),
        metavar="1-5",
        help="matching integrity observations required before automatic restoration (default: 2)",
    )
    controller.add_argument(
        "--allow-unprobed-restoration",
        action="store_true",
        help="permit automatic restoration without a mapped service/scoring probe (not recommended)",
    )
    controller.add_argument("--tls-cert")
    controller.add_argument("--tls-key")
    controller.add_argument(
        "--tls-ca-file",
        help="public controller trust anchor pinned by release.controller_ca_sha256",
    )
    controller.add_argument("--syslog-bind", help="enable agentless UDP syslog receiver on this address")
    controller.add_argument("--syslog-port", type=int, default=5514)
    controller.add_argument("--log-level", default="INFO")

    agent = subcommands.add_parser("agent", help="run a host telemetry agent")
    agent.add_argument("--controller", required=True)
    agent.add_argument(
        "--event-profile", required=True,
        help="private approved default-deny event profile/inventory JSON",
    )
    agent.add_argument(
        "--range-deployment",
        action="store_true",
        help=(
            "explicitly permit a checksum-pinned disposable range profile; "
            "never valid for a live competition profile"
        ),
    )
    agent_token = agent.add_mutually_exclusive_group()
    agent_token.add_argument("--token", help="bootstrap token; prefer --token-file")
    agent_token.add_argument("--token-file", help="one-time bootstrap token file deleted after enrollment")
    agent.add_argument(
        "--re-enroll",
        dest="reenroll",
        action="store_true",
        help=(
            "explicitly replace a revoked agent credential using a fresh "
            "ticket; never falls back automatically after authentication failure"
        ),
    )
    agent.add_argument("--agent-id")
    agent.add_argument("--interval", type=float, default=15.0)
    agent.add_argument(
        "--change-watch-interval",
        type=float,
        default=1.0,
        help="portable protected-file fingerprint fallback interval in seconds",
    )
    agent.add_argument("--state-dir", default=str(Path.home() / ".sentinel-blue"))
    agent.add_argument("--allow-containment", action="store_true")
    agent.add_argument(
        "--allow-restoration",
        action="store_true",
        help="permit live restoration from agent-local approved restore points",
    )
    agent.add_argument("--probe-config", help="JSON file containing scope-limited service probes")
    agent.add_argument("--ca-file", help="CA certificate for an HTTPS controller")
    agent.add_argument(
        "--expected-package-sha256",
        help="refuse controller actions if the deployed zipapp no longer matches this digest",
    )
    agent.add_argument("--spool-limit", type=int, default=256)
    agent.add_argument("--quarantine-ttl", type=float, default=300.0)
    agent.add_argument(
        "--authorized-network",
        action="append",
        default=[],
        help="authorized CIDR for probes; repeat as needed",
    )
    agent.add_argument("--once", action="store_true")
    agent.add_argument("--log-level", default="INFO")
    agent.add_argument(
        "--log-file",
        help="absolute rotating log path directly inside --state-dir",
    )
    agent.add_argument("--log-max-bytes", type=int, default=5 * 1024 * 1024)
    agent.add_argument("--log-backups", type=int, default=3)

    simulator = subcommands.add_parser("simulate", help="train and evaluate in the local simulated range")
    simulator.add_argument("--epochs", type=int, default=250)
    simulator.add_argument("--model-output", default="sentinel-blue-model.json")
    simulator.add_argument("--json", action="store_true")

    launcher = subcommands.add_parser("launcher", help="produce an authorized deployment plan")
    launcher.add_argument("--inventory", required=True)
    launcher.add_argument(
        "--event-profile",
        help="private approved profile JSON; defaults to --inventory when embedded",
    )
    launcher.add_argument("--package-url")
    launcher.add_argument("--package")
    launcher.add_argument("--checksum")
    launcher.add_argument("--controller")
    launcher.add_argument(
        "--ca-file",
        help="public controller trust anchor pinned by release.controller_ca_sha256",
    )
    launcher.add_argument(
        "--range-deployment",
        action="store_true",
        help="authorize only an exact checksum-bound disposable range profile",
    )
    launcher_token = launcher.add_mutually_exclusive_group()
    launcher_token.add_argument("--token")
    launcher_token.add_argument("--token-file")
    launcher.add_argument(
        "--preflight",
        action="store_true",
        help="run non-mutating package, configuration, and local transport readiness checks",
    )
    launcher.add_argument("--execute", action="store_true")
    launcher.add_argument("--yes", action="store_true", help="confirm execution against the inventory")

    learner = subcommands.add_parser("learn", help="train a regression-gated candidate from recorded decisions")
    learner.add_argument("--database", required=True)
    learner.add_argument("--base-model")
    learner.add_argument("--output", required=True)
    learner.add_argument("--campaign-id", required=True)
    learner.add_argument("--profile-id", required=True)
    learner.add_argument("--profile-fingerprint", required=True)
    learner.add_argument("--release-sha256", required=True)
    learner.add_argument("--agent-version", required=True)
    learner.add_argument("--model-fingerprint", required=True)

    range_command = subcommands.add_parser(
        "range", help="run an end-to-end disposable defensive range campaign"
    )
    range_command.add_argument("--runs", type=int, default=200)
    range_command.add_argument("--json", action="store_true")

    restoration_lab = subcommands.add_parser(
        "restoration-lab",
        help="run the disposable restoration and rollback attack campaign",
    )
    restoration_lab.add_argument("--runs", type=int, default=120)
    restoration_lab.add_argument("--json", action="store_true")

    policy_lab = subcommands.add_parser(
        "policy-lab",
        help="run the disposable competition-legality adversarial policy campaign",
    )
    policy_lab.add_argument("--runs", type=int, default=200)
    policy_lab.add_argument("--json", action="store_true")

    native_lab = subcommands.add_parser(
        "native-lab",
        help="run the owner-gated native campaign on a disposable GitHub-hosted runner",
    )
    native_lab.add_argument(
        "--output",
        help=(
            "report path; must resolve to "
            "GITHUB_WORKSPACE/native-live-report.json"
        ),
    )
    native_lab.add_argument("--json", action="store_true")

    doctor = subcommands.add_parser("doctor", help="run local readiness and package diagnostics")
    doctor.add_argument("--database")
    doctor.add_argument("--state-dir", default=str(Path.home() / ".sentinel-blue"))
    doctor.add_argument("--json", action="store_true")

    recovery_init = subcommands.add_parser(
        "recovery-init",
        help="offline initialize a controller database and protected anchor",
    )
    recovery_init.add_argument("--database", required=True)
    recovery_init.add_argument("--recovery-key-file", required=True)
    recovery_init.add_argument("--recovery-anchor", required=True)
    recovery_init.add_argument(
        "--enrollment-window",
        type=float,
        default=3600.0,
        help="initial enrollment window for a genuinely new database",
    )

    recovery_status = subcommands.add_parser(
        "recovery-status",
        help="offline verify live database freshness against its anchor",
    )
    recovery_status.add_argument("--database", required=True)
    recovery_status.add_argument("--recovery-key-file", required=True)
    recovery_status.add_argument("--recovery-anchor", required=True)

    recovery_backup = subcommands.add_parser(
        "recovery-backup",
        help="offline create and anchor an authenticated backup bundle",
    )
    recovery_backup.add_argument("--database", required=True)
    recovery_backup.add_argument("--output-directory", required=True)
    recovery_backup.add_argument("--recovery-key-file", required=True)
    recovery_backup.add_argument("--recovery-anchor", required=True)

    recovery_verify = subcommands.add_parser(
        "recovery-verify",
        help="authenticate and inspect a backup without restoring it",
    )
    recovery_verify.add_argument("--bundle", required=True)
    recovery_verify.add_argument("--recovery-key-file", required=True)
    recovery_verify.add_argument("--recovery-anchor", required=True)

    selftest = subcommands.add_parser(
        "self-test", help="run the packaged disposable range and recovery certification"
    )
    selftest.add_argument("--scenarios", type=int, default=300)
    selftest.add_argument("--fuzz-iterations", type=int, default=1500)
    selftest.add_argument("--load-events", type=int, default=750)
    selftest.add_argument(
        "--full",
        action="store_true",
        help="use the maximum 5,000 scenarios, 50,000 hostile inputs, and 50,000 load events",
    )
    selftest.add_argument("--json", action="store_true")

    return root


def main() -> None:
    args = parser().parse_args()
    if args.command in {"controller", "agent"}:
        from .config_validation import validate_bound_transport
        from .event_profile import load_event_profile

        event_profile = load_event_profile(args.event_profile)
        event_profile.require_runtime_ready(
            range_deployment=bool(getattr(args, "range_deployment", False))
        )
        if args.command == "controller":
            validate_bound_transport(
                event_profile,
                role="controller",
                ca_file=args.tls_ca_file,
                tls_cert=args.tls_cert,
                tls_key=args.tls_key,
                syslog_bind=args.syslog_bind,
            )
        else:
            validate_bound_transport(
                event_profile,
                role="agent",
                controller=args.controller,
                ca_file=args.ca_file,
            )
    if args.command == "controller":
        from .controller import run
    elif args.command == "agent":
        from .agent import run
    elif args.command == "simulate":
        from .simulator import run
    elif args.command == "learn":
        from .learning import run
    elif args.command == "range":
        from .range_lab import run
    elif args.command == "restoration-lab":
        from .restoration_lab import run
    elif args.command == "policy-lab":
        from .policy_lab import run
    elif args.command == "native-lab":
        from .native_range_lab import run
    elif args.command == "doctor":
        from .diagnostics import run
    elif args.command.startswith("recovery-"):
        from .recovery_ops import run
    elif args.command == "self-test":
        from .selftest import run
    else:
        from .launcher import run
    exit_code = run(args)
    if isinstance(exit_code, int) and exit_code != 0:
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
