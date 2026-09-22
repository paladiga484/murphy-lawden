#!/usr/bin/env python3
"""EZ-opt — the easy optimiser. Debloat a Linux box for max gameplay.

A standalone companion to Murphy Lawden, sharing Murphy's engine and its
reversible, amnesiac manners.  Usage:

    python ezopt.py [facet] [--apply]

    facets:  profile (default) · services · memory · cpu · io · restore
    --apply  actually make changes (default is a plan that touches nothing)

Everything is backed up before it's changed; `ezopt restore --apply` puts the
machine back exactly as it was.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from murphy_lawden.ezopt import run_ezopt
from murphy_lawden.banner import make_ink
from murphy_lawden import selfwipe


def main(argv=None):
    p = argparse.ArgumentParser(prog="ezopt", description="EZ-opt — debloat Linux for max gameplay.")
    p.add_argument("facet", nargs="?", default="profile",
                   choices=["profile", "services", "memory", "cpu", "io", "restore"],
                   help="what to optimise (default: profile = services+memory+cpu).")
    p.add_argument("--apply", dest="apply", action="store_true",
                   help="actually apply changes (default: plan only, touches nothing).")
    p.add_argument("--no-banner", action="store_true", help="skip the header art.")
    color = p.add_mutually_exclusive_group()
    color.add_argument("--no-color", action="store_true", help="disable ANSI colour.")
    color.add_argument("--color", action="store_true", help="force ANSI colour.")
    args = p.parse_args(argv)

    force = True if args.color else False if args.no_color else None
    ink = make_ink(force)
    # Amnesiac like Murphy: sweep runtime traces on the way out.
    selfwipe.arm_amnesia(incinerate_on_exit=False, ink=ink)
    return run_ezopt(args.facet, args.apply, ink=ink, banner=not args.no_banner)


if __name__ == "__main__":
    raise SystemExit(main())
