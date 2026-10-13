import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .engine import Engine
from .inputs import Scope, load_targets, normalize_url
from .network import DEFAULT_MAX_BYTES, Fetcher


class PlainParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def parser(advanced=False):
    root = PlainParser(
        prog="scriptlens",
        description="Find JavaScript requests and useful security review clues. "
        "Save everything as JSON.",
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser(
        "scan",
        help="fetch pages, scripts, imports and declared source maps",
        prog="scriptlens",
        description="Give a domain, URL, or list file. Fetch JavaScript and save results as JSON.",
        epilog="Examples:\n  scriptlens -u example.com\n"
        "  scriptlens -u https://example.com/\n  scriptlens -u domains.txt\n\n"
        "List files: one domain or URL per line; mixing both is OK.\n"
        "Bare domains use HTTPS. JSON is saved automatically in scriptlens-results/.\n"
        "For local JavaScript files: scriptlens analyze --help",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("targets", nargs="*", help="domains, URLs, list files, or '-' for stdin")
    scan.add_argument(
        "-u",
        "--url",
        action="append",
        default=[],
        dest="extra_targets",
        metavar="INPUT",
        help="domain, HTTP(S) URL, or domain/URL list file (repeatable)",
    )
    scan.add_argument(
        "-d",
        "--domain",
        action="append",
        dest="extra_targets",
        help=argparse.SUPPRESS,
    )
    scan.add_argument(
        "-l",
        "--list",
        action="append",
        default=[],
        dest="lists",
        help="hostname/URL list (repeatable)",
    )
    scan.add_argument(
        "--scope", action="append", default=[], help="also allow this domain and its subdomains"
    )
    scan.add_argument(
        "--asset-host",
        action="append",
        default=[],
        help="also allow scripts/maps from this exact hostname",
    )
    scan.add_argument("--max-pages", type=positive_int, default=10)
    scan.add_argument(
        "--depth", type=int, choices=range(0, 4), default=1, help="HTML link depth (default 1)"
    )
    scan.add_argument("--concurrency", type=positive_int, default=6)
    scan.add_argument(
        "--rate", type=positive_float, default=8, help="GET starts per second (default 8)"
    )
    scan.add_argument("--timeout", type=positive_float, default=12)
    scan.add_argument("--max-total-bytes", type=positive_int, default=80_000_000)
    scan.add_argument("--no-source-maps", action="store_true", help="skip declared source maps")
    scan.add_argument(
        "-k",
        "--insecure",
        "--no-ssl-verify",
        action="store_true",
        help="skip TLS certificate verification",
    )
    scan.add_argument(
        "--allow-private",
        action="store_true",
        help="allow private/loopback addresses for authorized labs",
    )
    local = commands.add_parser(
        "analyze", help="analyze local JS/TS or source-map files without network requests"
    )
    local.add_argument("files", nargs="+", type=Path)
    for command in (scan, local):
        command.add_argument("--help-all", action="help", help="show all advanced options")
        command.add_argument("--version", action="version", version=__version__)
        command.add_argument(
            "--max-bytes",
            type=positive_int,
            default=DEFAULT_MAX_BYTES,
            help="bytes per download or local file (default: 16000000)",
        )
        command.add_argument(
            "--max-nodes",
            type=positive_int,
            default=250_000,
            help="syntax nodes per source (default: 250000); higher values use more memory",
        )
        command.add_argument(
            "--base-url",
            type=normalize_url,
            help="document URL for resolving relative requests in direct JS inputs",
        )
        command.add_argument(
            "--max-files",
            type=positive_int,
            default=100,
            help="script/map download limit; also limits embedded sources",
        )
        command.add_argument(
            "-o",
            "--output",
            type=Path,
            help="new JSON file (default: timestamped file in scriptlens-results/)",
        )
        command.add_argument(
            "--color",
            choices=["auto", "always", "never"],
            default="auto",
            help="result-label colors only; help and JSON stay plain",
        )
        command.add_argument(
            "--raw", action="store_true", help="plain result lines without summary"
        )
        command.add_argument(
            "--max-output",
            type=positive_int,
            default=20,
            help="terminal result limit; JSON keeps everything",
        )
        command.add_argument(
            "--show-curl",
            action="store_true",
            help="also print curl templates for visible endpoints",
        )
        command.add_argument(
            "-v", "--verbose", action="store_true", help="show skipped/incomplete source details"
        )
        if not advanced:
            basic = {"help", "help_all", "extra_targets", "output", "files"}
            for action in command._actions:
                if action.dest not in basic:
                    action.help = argparse.SUPPRESS
    return root


def plain(value):
    value = str(value).encode("ascii", "backslashreplace").decode()
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", value)


def label(value, color, args):
    token = f"[{value}]"
    colored = (
        not args.raw
        and "NO_COLOR" not in os.environ
        and (
            args.color == "always"
            or (args.color == "auto" and sys.stdout.isatty() and os.environ.get("TERM") != "dumb")
        )
    )
    return f"\033[{color}m{token}\033[0m" if colored and color else token


def print_report(report, path, args):
    remaining = args.max_output
    for item in sorted(report["findings"], key=lambda x: x["priority"] != "high"):
        if remaining <= 0:
            break
        marker = label(
            "KEY" if item["priority"] == "high" else "REVIEW",
            "33" if item["priority"] == "high" else "35",
            args,
        )
        evidence = item["evidence"]
        print(f"{marker} {plain(item['title'])} - {plain(evidence['source'])}:{evidence['line']}")
        remaining -= 1
    for item in report["endpoints"]:
        if remaining <= 0:
            break
        marker = label(
            item["method"] or "CHECK",
            "36" if item["method"] in {"POST", "PUT", "PATCH", "DELETE"} else "",
            args,
        )
        body = item["body"]["value"]
        fields = (
            "; body: " + ", ".join(plain(k) for k in list(body)[:12])
            if isinstance(body, dict) and body
            else ""
        )
        print(f"{marker} {plain(item['url'] or item['url_template'])}{fields}")
        if args.show_curl and item["curl"]:
            print("  " + plain(item["curl"]))
        remaining -= 1
    if args.verbose:
        for item in report["diagnostics"]:
            print(f"[SKIP] {plain(item['source'])} - {plain(item['reason'])}")
            if item.get("hint"):
                print("  " + plain(item["hint"]))
    if not args.raw:
        summary = report["summary"]
        print(
            f"Done: {summary['analyzed_sources']} sources, {summary['endpoints']} endpoints, "
            f"{summary['review_items']} review items, {summary['incomplete']} incomplete."
        )
        if summary["incomplete"] and not args.verbose:
            problems = Counter(
                (d["reason"], d.get("hint", ""))
                for d in report["diagnostics"]
                if d["category"] == "incomplete"
            )
            for (reason, hint), count in problems.most_common(3):
                print(f"Incomplete ({count}): {plain(reason)}")
                if hint:
                    print("  " + plain(hint))
            print("Details: diagnostics in the JSON report, or rerun with -v.")
        if summary["review_items"] + summary["endpoints"] > args.max_output:
            print("More results are in the JSON report.")
        print("Saved: " + plain(path))


def run(args):
    if args.command == "scan":
        if args.concurrency > 32:
            raise ValueError("--concurrency must be 32 or less")
        targets = load_targets(args.targets + args.extra_targets, args.lists, sys.stdin)
        scope = Scope(targets, args.scope, args.asset_host)
        fetcher = Fetcher(
            scope,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
            max_total=args.max_total_bytes,
            concurrency=args.concurrency,
            rate=args.rate,
            insecure=args.insecure,
            allow_private=args.allow_private,
        )
        engine = Engine(
            fetcher,
            max_files=args.max_files,
            max_pages=args.max_pages,
            depth=args.depth,
            source_maps=not args.no_source_maps,
            base_url=args.base_url,
            max_nodes=args.max_nodes,
        )
    else:
        for path in args.files:
            if not path.is_file():
                raise ValueError(f"not a file: {path}")
        fetcher = Fetcher(Scope([]), max_bytes=args.max_bytes)
        engine = Engine(
            fetcher,
            max_files=args.max_files,
            source_maps=False,
            base_url=args.base_url,
            max_nodes=args.max_nodes,
        )
    output = args.output or Path("scriptlens-results") / (
        datetime.now(UTC).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3) + ".json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    exit_code = 0
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        try:
            if args.command == "scan":

                async def perform():
                    async with fetcher:
                        return await engine.run(targets)

                report = asyncio.run(perform())
            else:
                engine.report["targets"] = [str(path.resolve()) for path in args.files]
                for path in args.files:
                    if path.stat().st_size > fetcher.max_bytes:
                        engine.diagnostic(
                            str(path),
                            f"local file byte limit reached ({args.max_bytes:,} bytes)",
                            code="file_byte_limit",
                            hint="Increase --max-bytes for this file.",
                        )
                        continue
                    raw = path.read_bytes()
                    engine.report["sources"].append(
                        {
                            "url": str(path.resolve()),
                            "kind": "local",
                            "document_url": args.base_url,
                            "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                        }
                    )
                    if path.suffix == ".map":
                        engine.process_map(raw, str(path.resolve()), args.base_url)
                    else:
                        engine.process_code(raw, str(path.resolve()), args.base_url, discover=False)
                report = engine.finalize()
        except KeyboardInterrupt:
            engine.diagnostic("run", "interrupted; saved results are partial")
            report, exit_code = engine.finalize(), 130
        except Exception as exc:
            engine.diagnostic("run", f"{type(exc).__name__}: {exc}")
            report, exit_code = engine.finalize(), 2
        report["settings"] = {
            "tls_verification": not getattr(args, "insecure", False),
            "max_files": args.max_files,
            "max_bytes": args.max_bytes,
            "max_total_bytes": fetcher.max_total if args.command == "scan" else None,
            "max_nodes": args.max_nodes,
            "timeout_seconds": fetcher.timeout if args.command == "scan" else None,
            "base_url": args.base_url,
            "secrets_redacted": True,
            "mode": args.command,
        }
        report = engine.redactor.clean(report)
        json.dump(report, stream, indent=2, ensure_ascii=True)
        stream.write("\n")
    print_report(report, output, args)
    return exit_code or (3 if not report["complete"] else 0)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["--help"]
    if argv[0] not in {"scan", "analyze"}:
        argv.insert(0, "scan")
    args = parser(advanced="--help-all" in argv).parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, UnicodeError) as exc:
        print("error: " + plain(exc), file=sys.stderr)
        return 2
