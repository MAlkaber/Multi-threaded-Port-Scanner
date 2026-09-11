# Multi-threaded Port Scanner

**Project 03** of a pentest/red-team learning portfolio — see the [full roadmap](../ROADMAP.md).

Combines Project 01 (TCP connect scanning) and Project 02 (host
expansion) and adds concurrency, so you can scan hundreds or thousands of
host/port combinations in seconds instead of doing them one at a time.

> ⚠️ Only scan hosts/ranges you own or are explicitly authorized to test.
> Note also: aggressive thread counts against a real network can look
> like — and functionally behave like — a denial-of-service attempt.
> Keep `--threads` reasonable on anything but a lab you control.

## Why this project exists

Project 01 scanned 1024 ports on one host **sequentially** — one
`connect()`, wait up to the timeout, then the next. At a 1-second timeout
that's a worst-case of ~17 minutes for ports that don't respond. This
project runs many of those checks **at the same time**, so the total time
is closer to the slowest single check, not the sum of all of them. In the
test run in this repo's history: 1024 ports scanned in ~9 seconds with
200 threads.

## Concepts you need before reading the code

**Threads, in one paragraph.** A thread is an independent path of
execution inside the same program. Normally Python runs one thing at a
time, top to bottom. With threading, you can have many function calls
"in flight" simultaneously — while one is waiting on something slow (like
a network reply), another can be making progress.

**Why threading works here despite the GIL.** Python has a Global
Interpreter Lock (GIL) that only lets one thread execute Python bytecode
at a time — so threading does *not* speed up CPU-heavy work like hashing
or math. But `sock.connect_ex()` spends nearly all its time **waiting**
on the network, not executing Python code. While a thread is blocked
waiting for a TCP response, it releases the GIL, letting another thread
run. That's why threading is the right tool for *I/O-bound* work like
scanning, and the wrong tool for *CPU-bound* work (we'll use
`multiprocessing` for that kind of task in a later project).

**`ThreadPoolExecutor`.** Instead of manually creating and managing
individual `threading.Thread` objects, `ThreadPoolExecutor` keeps a fixed
pool of worker threads (`max_workers`) and hands each submitted job
(`pool.submit(...)`) to whichever worker is free. This is the modern,
safer way to use threading in Python — it handles the bookkeeping
(starting threads, joining them, propagating exceptions) for you.

**`Future` and `as_completed()`.** Every `pool.submit()` call returns a
`Future` object immediately — a placeholder for a result that doesn't
exist yet. `as_completed(futures)` yields each future *the moment it
finishes*, in whatever order that happens to be — not the order you
submitted them. That's what lets this script print open ports live as
they're discovered, rather than blocking until literally everything is
done.

## Code walkthrough

Open [`threaded_scanner.py`](threaded_scanner.py) alongside this section.

- **`expand_targets()` / `parse_ports()`** — the same target/port parsing
  logic from Projects 01–02, reimplemented here so this repo works
  standalone. Notice `expand_targets()` now also has to handle plain
  hostnames (`scanme.nmap.org`) correctly even when they contain a
  hyphen — `_looks_like_ip()` disambiguates "IP range" from "hostname
  with a dash in it".
- **`check_port()`** — identical scanning logic to Project 01, but it now
  returns `(host, port, is_open)` instead of just `is_open`. That's
  required because of how the results come back (see below).
- **`main()`** — builds a flat list of `(host, port)` job tuples (every
  host × every port), submits all of them to the pool at once, then
  drains results via `as_completed()` as they finish.

## Try it yourself (exercises)

1. Re-run the scan with `--threads 10` vs `--threads 200` vs
   `--threads 1000` against a small port range and compare the timing.
   Is more threads always faster? At what point does it stop helping (or
   start hurting)?
2. Right now, exceptions inside `check_port()` other than `gaierror` will
   propagate up when you call `future.result()` and crash the whole scan.
   Wrap that call in a `try/except` and make one bad host fail gracefully
   instead of killing the entire run.
3. Add a `--top-ports N` flag that scans the N most common ports (hardcode
   a short list like `[21,22,23,25,53,80,110,143,443,445,3389,8080]`)
   instead of requiring the user to type them out.
4. (Preview of Project 04) Once you know a port is open, the natural next
   question is *what's running on it*. Sketch how you'd read the first
   few bytes a server sends back right after connecting to guess the
   service — that's Project 04.

## Running it

```bash
git clone <your-repo-url>
cd 03-multithreaded-port-scanner
python3 threaded_scanner.py scanme.nmap.org 1-1024 --threads 200
python3 threaded_scanner.py 192.168.1.0/24 22,80,443 --threads 300   # lab network only
```

Standard library only — no `pip install` needed.

## What's next

**Project 04 — Banner Grabber:** once you've found an open port, read
what the service says back to identify what's actually running there
(SSH version, HTTP server header, etc.) instead of just "open/closed".
