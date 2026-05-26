#!/usr/bin/env python3
"""
nsgaslight.py

Check whether any IPs/ranges in List A overlap with List B.

Use case: client gave you a scope (List A) and an exclusion list (List B,
often incomplete or revised after the fact). Run this to catch any of your
in-scope targets that fall inside their stated exclusions BEFORE testing —
or to audit findings against a newly-produced "but that was excluded" list
AFTER the fact, so you've got receipts before the dispute meeting.

Both lists may contain a mix of single IPs (10.1.2.3) and CIDR ranges
(10.1.2.0/24), one entry per line. Blank lines and lines starting with #
are ignored.

A List A entry "matches" a List B entry if they share ANY address:
  - single IP in A inside a CIDR in B
  - single IP in A equal to single IP in B
  - CIDR in A overlaps (fully or partially) with a CIDR in B
  - CIDR in A contains a single IP in B

Usage:
    python3 nsgaslight.py <list_a> <list_b>
    python3 nsgaslight.py scope.txt exclusions.txt
    python3 nsgaslight.py scope.txt exclusions.txt --quiet
    python3 nsgaslight.py scope.txt exclusions.txt --only-matches

Exit codes:
    0  no overlap found (List A is clean)
    1  one or more overlaps found
    2  usage / file error
"""

import argparse
import ipaddress
import sys
from pathlib import Path


def load_list(path: Path, label: str):
    """Parse a file of IPs/CIDRs into [(original_line, lineno, network), ...]."""
    if not path.exists():
        print(f"[!] {label} file not found: {path}", file=sys.stderr)
        sys.exit(2)

    entries = []
    seen = set()
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Allow common delimiters in case someone pastes a comma/space list
        for token in line.replace(",", " ").split():
            try:
                # strict=False accepts entries like 172.17.40.226/16
                # where host bits are set (common in real-world lists)
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as e:
                print(f"[!] {path.name}:{lineno} - skipping '{token}': {e}",
                      file=sys.stderr)
                continue
            if net in seen:
                continue
            seen.add(net)
            entries.append((token, lineno, net))
    return entries


def find_overlaps(list_a, list_b):
    """For each entry in A, return matching entries from B."""
    results = []
    for a_token, a_lineno, a_net in list_a:
        matches = [(b_token, b_lineno, b_net)
                   for b_token, b_lineno, b_net in list_b
                   if a_net.overlaps(b_net)]
        results.append((a_token, a_lineno, a_net, matches))
    return results


def describe_overlap(a_net, b_net):
    """Human-readable overlap relation."""
    if a_net == b_net:
        return "identical"
    if a_net.subnet_of(b_net):
        return f"{a_net} fully inside {b_net}"
    if b_net.subnet_of(a_net):
        return f"{a_net} contains {b_net}"
    return f"{a_net} partially overlaps {b_net}"


def main():
    p = argparse.ArgumentParser(
        description="Find IPs/CIDRs from List A that overlap with List B.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Lists may contain single IPs (10.1.2.3) or CIDR (10.1.2.0/24).")
    p.add_argument("list_a", help="Targets / scope (IPs and/or CIDRs)")
    p.add_argument("list_b", help="Exclusions (IPs and/or CIDRs)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress per-entry 'clean' lines; show matches + summary only.")
    p.add_argument("-m", "--only-matches", action="store_true",
                   help="Only print the matched List A entries, one per line. "
                        "Good for piping into other tools.")
    args = p.parse_args()

    list_a = load_list(Path(args.list_a), "List A")
    list_b = load_list(Path(args.list_b), "List B")

    if not list_a:
        print("[!] List A is empty after parsing.", file=sys.stderr)
        sys.exit(2)
    if not list_b:
        print("[!] List B is empty after parsing.", file=sys.stderr)
        sys.exit(2)

    results = find_overlaps(list_a, list_b)
    matched = [r for r in results if r[3]]

    if args.only_matches:
        for a_token, _, _, _ in matched:
            print(a_token)
        sys.exit(1 if matched else 0)

    # Full human-readable report
    for a_token, a_lineno, a_net, matches in results:
        if matches:
            print(f"[X] {a_token}  (List A line {a_lineno})  -> EXCLUDED")
            for b_token, b_lineno, b_net in matches:
                print(f"      matches List B line {b_lineno}: {b_token}"
                      f"   [{describe_overlap(a_net, b_net)}]")
        elif not args.quiet:
            print(f"[ok] {a_token}  (List A line {a_lineno})")

    # Summary
    print()
    print(f"Summary: {len(matched)} of {len(list_a)} List A entries "
          f"overlap with List B ({len(list_b)} exclusion entries loaded).")

    sys.exit(1 if matched else 0)


if __name__ == "__main__":
    main()
