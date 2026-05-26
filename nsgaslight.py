#!/usr/bin/env python3
"""
nsgaslight.py — find IPs/CIDRs in a TARGET list that overlap with an EXCLUSION list.

Exit codes:
    0  no overlap found (TARGET is clean)
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


def find_overlaps(targets, exclusions):
    """For each target entry, return matching exclusion entries."""
    results = []
    for t_token, t_lineno, t_net in targets:
        matches = [(e_token, e_lineno, e_net)
                   for e_token, e_lineno, e_net in exclusions
                   if t_net.overlaps(e_net)]
        results.append((t_token, t_lineno, t_net, matches))
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
        description="Find IPs/CIDRs in the target list that overlap with the exclusion list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Lists may contain single IPs (10.1.2.3) or CIDR (10.1.2.0/24).")
    p.add_argument("target", help="Target / scope list (IPs and/or CIDRs)")
    p.add_argument("exclusion", help="Exclusion list (IPs and/or CIDRs)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write results to FILE instead of stdout.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose format: show which exclusion entry caught "
                        "each target, plus a summary line. Default is to "
                        "list matched target IPs only.")
    args = p.parse_args()

    targets = load_list(Path(args.target), "TARGET")
    exclusions = load_list(Path(args.exclusion), "EXCLUSION")

    if not targets:
        print("[!] TARGET list is empty after parsing.", file=sys.stderr)
        sys.exit(2)
    if not exclusions:
        print("[!] EXCLUSION list is empty after parsing.", file=sys.stderr)
        sys.exit(2)

    results = find_overlaps(targets, exclusions)
    matched = [r for r in results if r[3]]

    # Build the output as a list of lines based on format choice
    lines = []
    if not args.verbose:
        # Default: simple - matched target IPs only (suitable for piping)
        for t_token, _, _, _ in matched:
            lines.append(t_token)
    else:
        # Verbose: full table - every target, matched or clear, plus summary.
        # Column widths include ALL targets so clean rows align with matched.
        t_width = max((len(t_token) for t_token, _, _, _ in results),
                      default=0)
        e_width = max(
            [len(e_token) for _, _, _, ms in results for e_token, _, _ in ms]
            + [len("clear")],
            default=0)

        for t_token, t_lineno, t_net, ms in results:
            if not ms:
                lines.append(f"{t_token:<{t_width}}  →  clear")
                continue
            for i, (e_token, e_lineno, e_net) in enumerate(ms):
                target_col = t_token if i == 0 else ""
                partial = (t_net != e_net) and (not t_net.subnet_of(e_net))
                note = ", partial" if partial else ""
                lines.append(f"{target_col:<{t_width}}  →  "
                             f"{e_token:<{e_width}}  (line {e_lineno}{note})")

        lines.append("")
        lines.append(f"{len(matched)}/{len(targets)} excluded · "
                     f"{len(exclusions)} exclusions loaded")

    output_text = "\n".join(lines) + ("\n" if lines else "")

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"[+] Wrote {len(matched)}/{len(targets)} excluded entries "
              f"to {args.output}")
    else:
        sys.stdout.write(output_text)

    sys.exit(1 if matched else 0)


if __name__ == "__main__":
    main()
