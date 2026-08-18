#!/usr/bin/env python3
"""resolver_bench.py — one disciplined measurement cycle against one resolver.

The harness exists because ad-hoc measurement loops fail quietly: a dead
instance measures as zeros, a cold cache measures recursion instead of
serving, a stale process on a reuseport socket splits the load, and a shell
quirk turns a counter into garbage. Every phase here either passes loudly or
aborts loudly, and numbers only print when the gates held.

Phases:
  1. reachability - the resolver answers a corpus name at all
  2. warm         - resolve the whole corpus at bounded parallelism
  3. warm-verify  - a random sample must answer NOERROR, fast, at the
                    configured rate; one re-warm is attempted, then abort
  4. throwaway    - one unrecorded run to settle caches and scheduler
  5. measure      - N recorded runs with a pause between each
  6. cool-down    - a final quiet period so the next cycle starts clean

CPU accounting (--pids): utime+stime deltas from /proc/<pid>/stat across
each run, summed over the given pids — the server's own cost, with the load
generator excluded by construction. Threaded servers need one pid; per-
process servers (kresd) need the whole set.

Output: one TSV row per run on stdout
  label  run  qps  avg_latency_s  completed_pct  cpu_ticks  busy_cores  qps_per_core
followed by a summary row (label, "median"/"best"). Progress goes to stderr.

Example (the published UDP shape):
  resolver_bench.py --port 5391 --corpus hits.txt --label sdns \
      --pids "$(pgrep -x sdns-shards)"
"""

import argparse
import random
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def fail(msg: str) -> "sys.NoReturn":
    log(f"resolver-bench: FATAL: {msg}")
    sys.exit(1)


def run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}


def encode_query(qid: int, name: str) -> bytes:
    """A plain A/IN query, RD=1, no EDNS — the shape dnsperf sends. The
    root name (".") is a legitimate corpus entry and encodes as the bare
    null label."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b""
    stripped = name.rstrip(".")
    if stripped:
        for label in stripped.split("."):
            raw = label.encode("idna") if not label.isascii() else label.encode()
            if not 0 < len(raw) < 64:
                raise ValueError(f"bad label in {name!r}")
            qname += bytes([len(raw)]) + raw
    return header + qname + b"\x00" + struct.pack("!HH", 1, 1)


class Client:
    """Native UDP DNS questions against the resolver under test — one
    socket per thread, no subprocesses. ask() returns (rcode, rtt_ms)."""

    def __init__(self, port: int):
        self.addr = ("127.0.0.1", port)
        self.local = threading.local()

    def _sock(self) -> socket.socket:
        s = getattr(self.local, "sock", None)
        if s is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(self.addr)
            self.local.sock = s
        return s

    def ask(self, name: str, timeout_s: float = 2.0) -> tuple[str, float]:
        try:
            query = encode_query(random.getrandbits(16), name)
        except (ValueError, UnicodeError):
            return "BADNAME", -1.0
        s = self._sock()
        s.settimeout(timeout_s)
        start = time.monotonic()
        try:
            s.send(query)
            while True:
                reply = s.recv(4096)
                if len(reply) >= 12 and reply[:2] == query[:2]:
                    rtt = (time.monotonic() - start) * 1000.0
                    return RCODES.get(reply[3] & 0x0F, "OTHER"), rtt
        except (socket.timeout, OSError):
            return "TIMEOUT", -1.0


def cpu_ticks(pids: list[int]) -> int:
    """Summed utime+stime clock ticks; a vanished pid is a fatal event —
    measuring a dead server as zero cost is how bad numbers get published."""
    total = 0
    for pid in pids:
        try:
            fields = open(f"/proc/{pid}/stat").read().rsplit(") ", 1)[1].split()
            total += int(fields[11]) + int(fields[12])  # utime, stime
        except (FileNotFoundError, IndexError, ValueError):
            fail(f"pid {pid} disappeared or unreadable mid-measurement")
    return total


def reachability(client: Client, name: str, tries: int = 30) -> None:
    for _ in range(tries):
        rcode, _ = client.ask(name)
        if rcode in ("NOERROR", "NXDOMAIN", "SERVFAIL"):
            return
        time.sleep(1)
    fail(f"resolver on :{client.addr[1]} never answered '{name}' in {tries} tries")


def warm(client: Client, names: list[str], parallel: int) -> None:
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        list(pool.map(lambda n: client.ask(n, timeout_s=3.0), names))


def verify(client: Client, names: list[str], sample: int = 100,
           fast_ms: float = 100.0) -> int:
    """Percentage of a random sample answering NOERROR under fast_ms."""
    picks = random.sample(names, min(sample, len(names)))
    hits = 0
    for name in picks:
        rcode, ms = client.ask(name)
        if rcode == "NOERROR" and 0 <= ms < fast_ms:
            hits += 1
    return hits * 100 // len(picks)


DNSPERF_QPS = re.compile(r"Queries per second:\s+([\d.]+)")
DNSPERF_LAT = re.compile(r"Average Latency \(s\):\s+([\d.]+)")
DNSPERF_SENT = re.compile(r"Queries sent:\s+(\d+)")
DNSPERF_DONE = re.compile(r"Queries completed:\s+(\d+)")


def dnsperf(args, seconds: int) -> dict:
    cmd = ["dnsperf", "-s", "127.0.0.1", "-p", str(args.port),
           "-d", args.corpus, "-c", str(args.clients), "-T", str(args.threads),
           "-l", str(seconds)]
    if args.tcp:
        cmd[1:1] = ["-m", "tcp"]
    p = run(cmd, timeout=seconds + 30)
    if p.returncode != 0:
        fail(f"dnsperf exited {p.returncode}: {p.stderr.strip()[:200]}")
    qps = DNSPERF_QPS.search(p.stdout)
    if not qps:
        fail("dnsperf output had no 'Queries per second' line")
    lat = DNSPERF_LAT.search(p.stdout)
    sent = DNSPERF_SENT.search(p.stdout)
    done = DNSPERF_DONE.search(p.stdout)
    completed_pct = -1.0
    if sent and done and int(sent.group(1)) > 0:
        completed_pct = 100.0 * int(done.group(1)) / int(sent.group(1))
    return {
        "qps": float(qps.group(1)),
        "lat": float(lat.group(1)) if lat else -1.0,
        "completed_pct": completed_pct,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--label", default=None)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--run-len", type=int, default=20)
    ap.add_argument("--clients", type=int, default=None)
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--tcp", action="store_true")
    ap.add_argument("--pids", default="",
                    help="comma/space separated server pids for CPU accounting")
    ap.add_argument("--warm-par", type=int, default=16)
    ap.add_argument("--warm-verify-pct", type=int, default=95)
    ap.add_argument("--inter-run", type=int, default=10)
    ap.add_argument("--cooldown", type=int, default=45)
    args = ap.parse_args()

    args.label = args.label or str(args.port)
    if args.clients is None:
        args.clients = 20 if args.tcp else 128
    if args.threads is None:
        args.threads = 4 if args.tcp else 8
    pids = [int(p) for p in re.split(r"[,\s]+", args.pids) if p]

    try:
        names = [ln.split()[0] for ln in open(args.corpus) if ln.strip()]
    except OSError as e:
        fail(f"corpus: {e}")
    if not names:
        fail("corpus is empty")
    if subprocess.run(["which", "dnsperf"], capture_output=True).returncode != 0:
        fail("dnsperf not found")
    if pids:
        cpu_ticks(pids)  # fail now, not mid-measurement

    client = Client(args.port)

    log(f"[{args.label}] 1/6 reachability on :{args.port}")
    reachability(client, names[0])

    log(f"[{args.label}] 2/6 warming {len(names)} names at parallelism {args.warm_par}")
    warm(client, names, args.warm_par)

    pct = verify(client, names)
    if pct < args.warm_verify_pct:
        log(f"[{args.label}] 3/6 warm sample only {pct}% — re-warming once")
        time.sleep(5)
        warm(client, names, args.warm_par)
        pct = verify(client, names)
        if pct < args.warm_verify_pct:
            fail(f"cache never warmed ({pct}% < {args.warm_verify_pct}%) — "
                 "refusing to measure recursion and call it serving")
    log(f"[{args.label}] 3/6 warm verified: {pct}% of sample NOERROR <100ms")

    log(f"[{args.label}] 4/6 throwaway run")
    dnsperf(args, 10)
    time.sleep(args.inter_run)

    log(f"[{args.label}] 5/6 measuring {args.runs}×{args.run_len}s")
    results = []
    for r in range(1, args.runs + 1):
        t0 = cpu_ticks(pids) if pids else None
        m = dnsperf(args, args.run_len)
        t1 = cpu_ticks(pids) if pids else None
        row = dict(m)
        if pids:
            ticks = t1 - t0
            cores = ticks / 100.0 / args.run_len
            row.update(ticks=ticks, cores=cores,
                       qpc=(m["qps"] / cores if cores > 0 else 0.0))
        results.append(row)
        cpu = (f"\t{row['ticks']}\t{row['cores']:.2f}\t{row['qpc']:.0f}"
               if pids else "\t-\t-\t-")
        print(f"{args.label}\trun{r}\t{m['qps']:.0f}\t{m['lat']:.6f}"
              f"\t{m['completed_pct']:.1f}{cpu}", flush=True)
        if r < args.runs:
            time.sleep(args.inter_run)

    qpses = [x["qps"] for x in results]
    med, best = statistics.median(qpses), max(qpses)
    if pids:
        med_cores = statistics.median(x["cores"] for x in results)
        print(f"{args.label}\tsummary\tmedian={med:.0f}\tbest={best:.0f}"
              f"\tmedian_cores={med_cores:.2f}\tqps_per_core={med / med_cores:.0f}",
              flush=True)
    else:
        print(f"{args.label}\tsummary\tmedian={med:.0f}\tbest={best:.0f}", flush=True)

    log(f"[{args.label}] 6/6 cool-down {args.cooldown}s")
    time.sleep(args.cooldown)


if __name__ == "__main__":
    main()
