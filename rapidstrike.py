#!/usr/bin/env python3
"""
Bear Net RapidStrike — Layer 2 / Routing Assessment Framework

Usage:
    sudo python3 rapidstrike.py list
    sudo python3 rapidstrike.py <module> --help
    sudo python3 rapidstrike.py <module> [options] --engagement-id RoE-XXX --operator johto --client CLIENT

Authorized engagement use only. Every run is recorded in the audit log.
"""

import argparse
import sys

from core.authz import BANNER, add_engagement_args, engagement_from_args
from core.logging_util import build_logger
from modules import MODULES


def build_parser():
    parser = argparse.ArgumentParser(
        prog="rapidstrike.py",
        description="Bear Net RapidStrike — Layer 2 / Routing Assessment Framework\n"
                    "Authorized engagements only. Every run is logged.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run  sudo python3 rapidstrike.py list  to see all modules.",
    )
    parser.add_argument(
        "--log", default="rapidstrike_audit.log",
        help="Audit log path (default: rapidstrike_audit.log)",
    )
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")

    subparsers = parser.add_subparsers(dest="module", metavar="<module>")
    subparsers.add_parser("list", help="List available modules")

    for module in MODULES:
        module.register(subparsers, add_engagement_args)

    return parser


def print_module_list():
    col_w = 12
    print(f"\n{'Module':<{col_w}} {'ATT&CK':<14} Description")
    print("─" * 80)
    for m in MODULES:
        name   = getattr(m, "NAME",        "?")
        attck  = getattr(m, "ATTCK_ID",    "—")
        desc   = getattr(m, "DESCRIPTION", "")
        print(f"{name:<{col_w}} {attck:<14} {desc}")
    print()
    print(f"Total: {len(MODULES)} modules")
    print("Usage: sudo python3 rapidstrike.py <module> --help\n")


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.module:
        parser.print_help()
        return 1

    if args.module == "list":
        if not getattr(args, "no_banner", False):
            print(BANNER)
        print_module_list()
        return 0

    if not getattr(args, "no_banner", False):
        print(BANNER)

    engagement = engagement_from_args(args)
    logger     = build_logger("rapidstrike", args.log, engagement)

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1

    try:
        return func(args, logger) or 0
    except PermissionError:
        logger.error("Permission denied — root / CAP_NET_RAW required for raw sockets.")
        return 1
    except KeyboardInterrupt:
        logger.info("Stopped by operator.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
