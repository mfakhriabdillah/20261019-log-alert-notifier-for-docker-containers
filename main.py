```python
#!/usr/bin/env python3
"""
Log Alert Notifier for Docker Containers
A CLI tool for cloud/DevOps engineers to monitor container logs and trigger alerts.
"""

import argparse
import json
import logging
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

try:
    import docker
except ImportError:
    docker = None

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FMT = "%Y-%m-%d %H:%M:%S"


class LogPatternMatcher:
    """Matches log lines against user-defined regex patterns and thresholds."""

    def __init__(self) -> None:
        self._patterns: Dict[str, Pattern] = {}
        self._counts: Dict[str, int] = defaultdict(int)
        self._window_start: float = time.time()

    def add_pattern(self, name: str, regex: str, threshold: int = 1, case_sensitive: bool = True) -> None:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            self._patterns[name] = re.compile(regex, flags)
        except re.error as exc:
            raise ValueError(f"Invalid regex '{regex}' for pattern '{name}': {exc}") from exc
        self._counts[name] = 0
        logging.debug("Registered alert pattern '%s': %s (threshold=%d)", name, regex, threshold)

    def reset_window(self) -> None:
        self._counts.clear()
        self._window_start = time.time()

    def check(self, line: str) -> List[Tuple[str, int]]:
        """Scan one log line and return list of (pattern_name, current_count) matches."""
        results: List[Tuple[str, int]] = []
        for name, pat in self._patterns.items():
            if pat.search(line):
                self._counts[name] += 1
                results.append((name, self._counts[name]))
        return results

    def get_exceeded(self, thresholds: Dict[str, int]) -> List[Tuple[str, int, int]]:
        """Return patterns whose count meets or exceeds the configured threshold."""
        exceeded: List[Tuple[str, int, int]] = []
        for name, count in self._counts.items():
            thresh = thresholds.get(name, 0)
            if thresh > 0 and count >= thresh:
                exceeded.append((name, count, thresh))
        return exceeded


class DockerLogFetcher:
    """Abstracts Docker log streaming for containers."""

    def __init__(self, client: Optional["docker.DockerClient"] = None, timeout: int = 30) -> None:
        if docker is None:
            raise RuntimeError("docker-py not installed. Run: pip install docker")
        self._client = client or docker.from_env()
        self._timeout = timeout

    def list_containers(self, all_containers: bool = False) -> List[Dict[str, str]]:
        filter_flag = "all" if all_containers else "running"
        containers = self._client.containers.list(all=all_containers)
        result = []
        for c in containers:
            result.append({
                "id": c.short_id,
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else str(c.image),
            })
        return result

    def get_log_tail(self, container_name: str, tail_lines: int = 500) -> List[str]:
        """Fetch the last N lines from a container's logs (sync, one-shot)."""
        try:
            ctr = self._client.containers.get(container_name)
        except docker.errors.NotFound as exc:
            raise RuntimeError(f"Container '{container_name}' not found") from exc
        logs_bytes = ctr.logs(stdout=True, stderr=True, timestamps=True, tail=tail_lines)
        if isinstance(logs_bytes, bytes):
            text = logs_bytes.decode("utf-8", errors="replace")
        else:
            text = str(logs_bytes)
        return text.splitlines()

    def stream_logs(self, container_name: str, callback, tail_lines: int = 0) -> None:
        """Stream logs from a container, invoking callback(line) for each new line."""
        try:
            ctr = self._client.containers.get(container_name)
        except docker.errors.NotFound as exc:
            raise RuntimeError(f"Container '{container_name}' not found") from exc
        logs = ctr.logs(stdout=True, stderr=True, timestamps=True, follow=True, stream=True, tail=tail_lines)
        for raw in logs:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line:
                callback(line)

    def inspect_container(self, container_name: str) -> Dict:
        try:
            ctr = self._client.containers.get(container_name)
            return ctr.attrs
        except docker.errors.NotFound as exc:
            raise RuntimeError(f"Container '{container_name}' not found") from exc


class AlertFormatter:
    """Formats alert payloads for various notification channels."""

    @staticmethod
    def format_text(
        container_name: str,
        patterns: List[Tuple[str, int, int]],
        sample_lines: List[str],
        since: datetime,
    ) -> str:
        lines = [
            f"=== Log Alert: {container_name} ===",
            f"Time: {since.strftime(DATE_FMT)}",
            f"Triggered patterns:",
        ]
        for name, count, thresh in patterns:
            lines.append(f"  [{name}] count={count} threshold={thresh}")
        if sample_lines:
            lines.append("Sample matching lines:")
            for sl in sample_lines[-5:]:
                lines.append(f"    {sl[:200]}")
        return "\n".join(lines)

    @staticmethod
    def format_json(
        container_name: str,
        patterns: List[Tuple[str, int, int]],
        sample_lines: List[str],
        since: datetime,
    ) -> str:
        payload = {
            "timestamp": since.isoformat(),
            "container": container_name,
            "alerts": [
                {"pattern": name, "count": count, "threshold": thresh}
                for name, count, thresh in patterns
            ],
            "sample_lines": [sl[:500] for sl in sample_lines[-10:]],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-alert-notifier",
        description="Monitor Docker container logs and trigger alerts on pattern matches.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-shot scan of a container's recent logs
  log-alert-notifier --container myapp --pattern "ERROR|FATAL" --pattern-severity "error:1"

  # Stream logs continuously with multiple patterns
  log-alert-notifier --container myapp --stream --interval 60 \\
      --pattern-severity "error:3,exception:2,timeout:1"

  # Dry-run with verbose output
  log-alert-notifier --container myapp --stream --dry-run --verbose
        """,
    )
    parser.add_argument("-c", "--container", help="Container name or ID to monitor")
    parser.add_argument(
        "--all-containers",
        action="store_true",
        help="List all containers (implies --no-stream mode)",
    )
    parser.add_argument(
        "-p", "--pattern",
        action="append",
        metavar="REGEX",
        help="Regex pattern to match in logs (can be repeated)",
    )
    parser.add_argument(
        "--pattern-severity",
        metavar="NAME:THRESHOLD",
        action="append",
        help="Attach severity name and threshold count to the last --pattern (can be repeated)",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        default=False,
        help="Match patterns case-sensitively (default: case-insensitive)",
    )
    parser.add_argument(
        "--tail",
        type=int,
        default=500,
        metavar="LINES",
        help="Number of recent log lines to scan (default: 500)",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream logs in real-time instead of one-shot scan",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Seconds between alert windows in stream mode (default: 30)",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Alert output format (default: text)",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write log entries to this file in addition to stdout",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse patterns only; print config and exit without connecting to Docker",
    )
    parser.add_argument(
        "--notify-cmd",
        metavar="CMD",
        help="Shell command to execute when an alert fires. "
             "Placeholders: {alert}, {container}, {format}. "
             "Use --output text/json to control content format.",
    )
    return parser


def parse_severity_specs(specs: Optional[List[str]], case_sensitive: bool) -> Tuple[LogPatternMatcher, Dict[str, int]]:
    matcher = LogPatternMatcher()
    thresholds: Dict[str, int] = {}
    if not specs:
        return matcher, thresholds
    for spec in specs:
        if ":" not in spec:
            logging.warning("Skipping malformed severity spec '%s' (expected NAME:THRESHOLD)", spec)
            continue
        name, thresh_str = spec.rsplit(":", 1)
        try:
            thresh = int(thresh_str)
        except ValueError:
            logging.warning("Invalid threshold '%s' in spec '%s', skipping", thresh_str, spec)
            continue
        thresholds[name] = thresh
    return matcher, thresholds


def send_alert(
    container_name: str,
    patterns: List[Tuple[str, int, int]],
    sample_lines: List[str],
    since: datetime,
    fmt: str,
    notify_cmd: Optional[str],
) -> None:
    formatter = AlertFormatter()
    if fmt == "json":
        body = formatter.format_json(container_name, patterns, sample_lines, since)
    else:
        body = formatter.format_text(container_name, patterns, sample_lines, since)

    print("\n" + body)
    logging.info("Alert fired for '%s': %d pattern(s) exceeded threshold", container_name, len(patterns))

    if notify_cmd:
        alert_var = body if fmt == "text" else body
        cmd = notify_cmd.format(alert=alert_var, container=container_name, format=fmt)
        logging.debug("Executing notify command: %s", cmd)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.stdout:
                logging.debug("Notify stdout: %s", result.stdout.strip())
            if result.returncode != 0:
                logging.error("Notify command failed (rc=%d): %s", result.returncode, result.stderr.strip())
        except subprocess.TimeoutExpired:
            logging.error("Notify command timed out after 30s")
        except Exception as exc:
            logging.error("Notify command raised: %s", exc)


def do_stream(
    fetcher: DockerLogFetcher,
    container_name: str,
    matcher: LogPatternMatcher,
    thresholds: Dict[str, int],
    interval: int,
    fmt: str,
    notify_cmd: Optional[str],
    dry_run: bool,
) -> int:
    sample_lines: List[str] = []
    window_start = datetime.utcnow()

    def on_line(line: str) -> None:
        nonlocal sample_lines, window_start
        matches = matcher.check(line)
        for _, count in matches:
            if count <= thresholds.get(list(thresholds.keys())[0], 999999) if thresholds else False:
                pass
        # Keep last N sample lines per exceeded pattern
        for pat_name, cur_count in matches:
            if pat_name in thresholds and cur_count == thresholds[pat_name]:
                sample_lines.append(line)
        exceeded = matcher.get_exceeded(thresholds)
        if exceeded:
            now = datetime.utcnow()
            if dry_run:
                print(f"[DRY-RUN] Would alert at {now.isoformat()} for {container_name}: {exceeded}")
            else:
                send_alert(container_name, exceeded, sample_lines[-20:], window_start, fmt, notify_cmd)
            sample_lines.clear()
            window_start = now
            matcher.reset_window()

    print(f"Streaming logs from '{container_name}' (interval={interval}s) ... Ctrl-C to stop.")
    logging.info("Starting stream mode for container '%s'", container_name)
    try:
        fetcher.stream_logs(container_name, callback=on_line)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 0
    except Exception as exc:
        logging.error("Stream error: %s", exc)
        return 1
    return 0


def do_scan(
    fetcher: DockerLogFetcher,
    container_name: str,
    matcher: LogPatternMatcher,
    thresholds: Dict[str, int],
    tail_lines: int,
    fmt: str,
    notify_cmd: Optional[str],
    dry_run: bool,
) -> int:
    try:
        lines = fetcher.get_log_tail(container_name, tail_lines)
    except RuntimeError as exc:
        logging.error("%s", exc)
        return 1

    logging.info("Scanned %d lines from '%s'", len(lines), container_name)
    sample_lines: List[str] = []
    window_start = datetime.utcnow()

    for line in lines:
        matches = matcher.check(line)
        for pat_name, _ in matches:
            if pat_name in thresholds:
                sample_lines.append(line)
                break

    exceeded = matcher.get_exceeded(thresholds)
    if not exceeded:
        print(f"No alerts for '{container_name}' — all patterns below threshold.")
        return 0

    if dry_run:
        print(f"[DRY-RUN] Would alert for {container_name}: {exceeded}")
        return 0

    send_alert(container_name, exceeded, sample_lines[-20:], window_start, fmt, notify_cmd)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        try:
            args.log_file.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
        except OSError as exc:
            print(f"Error opening log file: {exc}", file=sys.stderr)
            return 2
    logging.basicConfig(level=log_level, format=LOG_FORMAT, datefmt=DATE_FMT, handlers=handlers)

    if not args.container and not args.all_containers:
        parser.print_help()
        print("\nError: --container or --all-containers is required.", file=sys.stderr)
        return 2

    if args.all_containers:
        try:
            fetcher = DockerLogFetcher()
            containers = fetcher.list_containers(all_containers=True)
            print(f"Found {len(containers)} container(s):")
            for c in containers:
                print(f"  {c['name']} ({c['id']}) — {c['status']} — image: {c['image']}")
            return 0
        except RuntimeError as exc:
            logging.error("%s", exc)
            return 1

    if not args.pattern and not args.pattern_severity:
        print("Error: At least one --pattern or --pattern-severity is required.", file=sys.stderr)
        return 2

    thresholds: Dict[str, int] = {}
    if args.pattern_severity:
        _, thresholds = parse_severity_specs(args.pattern_severity, args.case_sensitive)
    # Auto-assign severity names to patterns if none provided
    if args.pattern and not args.pattern_severity:
        for i, pat in enumerate(args.pattern):
            name = f"pattern_{i + 1}"
            thresholds[name] = 1
            logging.debug("Auto-assigned severity '%s' to pattern %d", name, i + 1)

    matcher = LogPatternMatcher()
    for i, pat_regex in enumerate(args.pattern or []):
        name = f"pattern_{i + 1}"
        matcher.add_pattern(name, pat_regex, case_sensitive=args.case_sensitive)

    if args.dry_run:
        print("=== DRY-RUN CONFIG ===")
        print(f"Container : {args.container}")
        print(f"Patterns  : {args.pattern or 'none'}")
        print(f"Thresholds: {thresholds}")
        print(f"Output    : {args.output}")
        print(f"Tail lines: {args.tail}")
        print(f"Stream    : {args.stream}")
        print(f"Interval  : {args.interval}")
        print("=====================")
        return 0

    try:
        fetcher = DockerLogFetcher()
    except RuntimeError as exc:
        logging.error("%s", exc)
        return 1

    if args.stream:
        return do_stream(fetcher, args.container, matcher, thresholds, args.interval, args.output, args.notify_cmd, args.dry_run)

    return do_scan(fetcher, args.container, matcher, thresholds, args.tail, args.output, args.notify_cmd, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
```