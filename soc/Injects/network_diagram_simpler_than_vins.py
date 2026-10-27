#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Circle, Ellipse, FancyBboxPatch, Rectangle

# Device colors, abbreviations, and common OS aliases.
COLORS = {"linux": "#16a34a", "windows": "#2563eb",
          "soc": "#dc2626", "host": "#64748b"}
SYMBOLS = {"linux": "L", "windows": "W", "soc": "SOC", "host": "PC"}
ALIASES = {
    "kali": "linux", "ubuntu": "linux", "debian": "linux", "rhel": "linux",
    "win": "windows", "win10": "windows", "win11": "windows",
    "siem": "soc", "analyst": "soc", "pc": "host", "other": "host",
}


def read_hosts(args):
    """Read hosts from CSV, command line, or interactive input."""
    if args.file:
        with open(args.file, newline="", encoding="utf-8-sig") as f:
            return [{k.strip().lower(): v for k, v in row.items() if k}
                    for row in csv.DictReader(f)]

    if args.ips:
        source = " ".join(args.ips)
    else:
        print("Enter IPs (e.g. 10.0.0.5=web:linux). Blank line finishes:")
        lines = []
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                break
            if not line:
                break
            lines.append(line)
        source = " ".join(lines)

    hosts = []
    for token in re.split(r"[,\s]+", source.strip()):
        if not token:
            continue
        dtype = "host"
        # Preserve colons in IPv6 addresses. Only known suffixes are types.
        if ":" in token:
            head, suffix = token.rsplit(":", 1)
            normalized = ALIASES.get(suffix.lower(), suffix.lower())
            if normalized in COLORS:
                token, dtype = head, normalized
        ip, _, name = token.partition("=")
        hosts.append({"ip": ip, "hostname": name, "type": dtype})
    return hosts


def validate_hosts(raw, prefix):
    """Remove bad/duplicate IPs, then group by IPv4 prefix or IPv6 /64."""
    valid = []
    seen = set()
    for host in raw:
        address = str(host.get("ip", "")).strip()
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            print(f"Skipping invalid IP: {address}")
            continue
        if ip in seen:
            print(f"Skipping duplicate: {ip}")
            continue
        seen.add(ip)
        dtype = str(host.get("type", "") or "host").lower().strip()
        dtype = ALIASES.get(dtype, dtype)
        if dtype not in COLORS:
            dtype = "host"
        net = ipaddress.ip_network(f"{ip}/{prefix if ip.version == 4 else 64}", strict=False)
        valid.append({"ip": str(ip), "hostname": str(host.get("hostname", "") or "").strip(),
                      "type": dtype, "subnet": str(net),
                      "scope": "public" if ip.is_global else "internal", "version": ip.version})
    return sorted(valid, key=lambda h: (h["version"], int(ipaddress.ip_address(h["ip"]))))


def round_box(ax, x, y, w, h, color, alpha=1, border=None, z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                               boxstyle="round,pad=0.08,rounding_size=0.15",
                               fc=color, ec=border or color, lw=1.3,
                               alpha=alpha, zorder=z))


def draw_host(ax, host, x, y, external=False):
    """A tiny monitor symbol, with color indicating device type."""
    color = COLORS[host["type"]]
    round_box(ax, x - 0.35, y - 0.05, 0.7, 0.43, "white", border=color, z=5)
    round_box(ax, x - 0.28, y + 0.02, 0.56, 0.27, color, z=6)
    ax.text(x, y + 0.155, SYMBOLS[host["type"]], color="white", weight="bold",
            fontsize=8, ha="center", va="center", zorder=7)
    ax.add_patch(Rectangle((x - 0.025, y - 0.17), 0.05, 0.1, color="#475569", zorder=5))
    ax.plot([x - 0.16, x + 0.16], [y - 0.17, y - 0.17], color="#475569", lw=2, zorder=5)
    label_y = y + 0.58 if external else y - 0.40
    vertical_align = "bottom" if external else "top"
    offset = 0.27 if external else -0.28
    if host["hostname"]:
        ax.text(x, label_y, host["hostname"][:24], weight="bold", fontsize=8,
                ha="center", va=vertical_align)
        ax.text(x, label_y + offset, host["ip"], color="#475569", fontsize=7,
                ha="center", va=vertical_align)
    else:
        ax.text(x, label_y, host["ip"], fontsize=8, ha="center", va=vertical_align)


def make_diagram(hosts, output, title, per_row):
    """Draw logical subnet groups connected to a core router."""
    subnets = defaultdict(list)
    external = []
    for host in hosts:
        if host["scope"] == "public":
            external.append(host)
        else:
            subnets[host["subnet"]].append(host)

    # Horizontal subnet zones; hosts wrap when --per-row is reached.
    zones = []
    cursor = 0.4
    max_rows = 1
    for name, group in subnets.items():
        cols = min(len(group), per_row)
        rows = (len(group) + cols - 1) // cols
        width = max(3.5, cols * 1.85 + 0.5)
        zones.append((name, group, cursor, width, cols, rows))
        cursor += width + 0.7
        max_rows = max(max_rows, rows)

    total_width = max(cursor, 8, len(external) * 1.85 + 2)
    zone_offset = (total_width - cursor) / 2 if zones else 0
    zones = [(name, group, left + zone_offset, width, cols, rows)
             for name, group, left, width, cols, rows in zones]
    center = total_width / 2
    bottom = -1.5 * (max_rows - 1) - 1.35
    top = 7.7 if external else 4.65
    fig, ax = plt.subplots(figsize=(max(11, total_width * 1.25),
                                    max(7, (top - bottom) * 1.1)))
    fig.patch.set_facecolor("white")
    ax.set(xlim=(-0.3, total_width + 0.3), ylim=(bottom - 0.35, top))
    ax.axis("off")

    # Draw connections first so devices appear in front of lines.
    switch_x = []
    for index, (name, group, left, width, cols, rows) in enumerate(zones, 1):
        sx = left + width / 2
        switch_x.append(sx)
        height = 2.9 + (rows - 1) * 1.5
        round_box(ax, left, 2.15 - height, width - 0.15, height,
                  "#f8fafc", border="#cbd5e1", z=0)
        ax.text(left + 0.17, 1.91, name, fontsize=9, weight="bold", color="#334155")
        ax.text(left + 0.17, 1.62, f"{len(group)} hosts", fontsize=7, color="#64748b")

        ax.plot([sx, sx], [2.65, 1.13], color="#64748b", lw=1.8, zorder=1)
        round_box(ax, sx - 0.35, 1.0, 0.7, 0.28, "#0f766e", z=5)
        ax.text(sx, 1.14, f"SW{index}", color="white", fontsize=7,
                weight="bold", ha="center", va="center", zorder=6)

        for i, host in enumerate(group):
            row, col = divmod(i, cols)
            x = sx + (col - (cols - 1) / 2) * 1.85
            y = 0.10 - row * 1.5
            ax.plot([sx, sx, x, x], [1.0, y + 0.58, y + 0.58, y + 0.38],
                    color="#94a3b8", lw=1.2, zorder=1)
            draw_host(ax, host, x, y)

    if switch_x:
        ax.plot([min(switch_x), max(switch_x)], [2.65, 2.65],
                color="#334155", lw=2, zorder=1)
        ax.plot([center, center], [3.50, 2.65], color="#334155", lw=2, zorder=1)

    ax.add_patch(Circle((center, 3.75), 0.28, fc="#2563eb", ec="#1e40af", lw=1.2, zorder=5))
    ax.text(center, 3.75, "R1", color="white", ha="center", va="center",
            fontsize=9, weight="bold", zorder=6)
    ax.text(center + 0.4, 3.75, "Core router", fontsize=9, va="center", weight="bold")

    if external:
        ax.plot([center, center], [4.04, 5.25], ls="--", color="#64748b", lw=1.7)
        ax.add_patch(Ellipse((center, 5.40), 1.5, 0.65, fc="#dbeafe", ec="#60a5fa", lw=1.5))
        ax.text(center, 5.40, "Internet", ha="center", va="center", fontsize=9, weight="bold")
        for i, host in enumerate(external):
            x = center + (i - (len(external) - 1) / 2) * 1.85
            ax.plot([center, center, x, x], [5.73, 5.98, 5.98, 6.25],
                    ls="--", color="#64748b", lw=1.1)
            draw_host(ax, host, x, 6.45, external=True)

    ax.text(0, 1.04, title, transform=ax.transAxes, fontsize=19,
            weight="bold", ha="left", color="#0f172a")
    ax.text(0, 1.005, f"{len(hosts)} devices  •  {len(subnets)} internal subnet(s)  •  Logical diagram (inferred)",
            transform=ax.transAxes, fontsize=9, ha="left", color="#64748b")
    legend = "    ".join(f"{SYMBOLS[t]} = {t.title()}" for t in COLORS)
    ax.text(0, -0.035, legend, transform=ax.transAxes, fontsize=9,
            color="#475569", ha="left")
    fig.savefig(output, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Create a logical network diagram from IPs")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--ips", nargs="+", help="IP[=hostname][:type] entries")
    source.add_argument("--file", help="CSV with ip,hostname,type columns")
    parser.add_argument("--prefix", type=int, default=24, help="IPv4 subnet prefix (default: 24)")
    parser.add_argument("--per-row", type=int, default=6, help="Hosts per row in each subnet")
    parser.add_argument("-o", "--output", default="network_diagram.png", help="PNG, SVG, or PDF filename")
    parser.add_argument("--title", default="Network Diagram")
    parser.add_argument("--show", action="store_true", help="Open saved diagram")
    args = parser.parse_args()

    if not 0 <= args.prefix <= 32 or args.per_row < 1:
        parser.error("--prefix must be 0-32 and --per-row must be at least 1")
    hosts = validate_hosts(read_hosts(args), args.prefix)
    if not hosts:
        parser.error("No valid IPs provided")

    downloads = Path.home() / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    output = downloads / Path(args.output).name
    with output.with_name(output.stem + "_inventory.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "hostname", "type", "subnet", "scope", "version"])
        writer.writeheader()
        writer.writerows(hosts)

    make_diagram(hosts, output, args.title, args.per_row)
    print(f"Saved diagram: {output}")
    print(f"Saved inventory: {output.with_name(output.stem + '_inventory.csv')}")
    if args.show:
        import webbrowser
        webbrowser.open(output.resolve().as_uri())


if __name__ == "__main__":
    main()
