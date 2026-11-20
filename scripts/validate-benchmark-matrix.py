"""Validate a benchmark matrix bundle: schema, verdicts, digests, freshness.

Re-derives every verdict from its interval with the whole-interval rule and
every median from its repeats, so a matrix-results.json that disagrees with
its own cells fails. Checks the manifest digests against the committed cell
files, the PNGs it claims exist, and the README table against the medians it
prints. Mirrors `upstream/zeronet/.../validate_results.py:11` and the
`revalidate` this workspace runs on every result.json: a report nobody can
re-derive is a report nobody can check.
"""

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchstats

REQUIRED_CELL_KEYS = {
    "scenario",
    "workload",
    "machine",
    "reference",
    "engines",
    "rows",
    "gate_passed",
    "failures",
    "harness_ceilings_mib_s",
}
REQUIRED_RESULTS_KEYS = {
    "version",
    "tier",
    "date",
    "host",
    "repeats",
    "reference",
    "scenarios",
    "manifest",
}
SETUP_CHART = "setup-latency.png"
THROUGHPUT_ENGINES = [
    "xray-core",
    "ferrox",
    "aether",
    "xray-core-rust",
    "zeronet",
    "sing-box",
    "xray-rust",
    "leaf",
]
MEDIAN_METRICS = (
    "throughput_mib_s",
    "cpu_millis_per_gib",
    "rss_mib",
    "threads_peak",
    "startup_seconds",
    "kernel_calls_per_gib",
    "transfer_seconds",
)

failures = []


def fail(message):
    """Collect rather than raise: one run reports every disagreement."""
    failures.append(message)


def check(condition, message):
    """Record a failed expectation without stopping the rest of the checks."""
    if not condition:
        fail(message)


def load_json(path):
    """Parsed JSON or a recorded failure."""
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        fail(f"unreadable JSON {path}: {exc}")
        return None


def check_cell(path):
    """Schema plus re-derived verdicts for one cell document."""
    doc = load_json(path)
    if doc is None:
        return None
    missing = REQUIRED_CELL_KEYS - set(doc)
    check(not missing, f"{path}: missing keys {sorted(missing)}")
    for row in doc.get("rows", []):
        interval = row.get("interval")
        pair = None
        if interval is not None:
            pair = (interval.get("low"), interval.get("high"))
            check(
                all(isinstance(v, (int, float)) for v in pair),
                f"{path}: interval is not numeric in {row.get('label')}",
            )
        expected = benchstats.verdict_for(pair, row.get("direction"))
        check(
            row.get("verdict") == expected,
            f"{path}: verdict {row.get('verdict')} re-derives to "
            f"{expected} in {row.get('label')}",
        )
    check_repeat_digests(path, doc)
    return doc


def check_repeat_digests(path, doc):
    """Every repeat of an engine names the same binary as the cell header.

    A cell whose repeats ran different binaries is a comparison against two
    things, which reads as one row. The per-repeat result.json files carry
    their own digest; they must all agree with each other and the header.
    """
    runs_dir = Path(path).parent / "runs"
    if not runs_dir.is_dir():
        return
    by_engine = {}
    for result in sorted(runs_dir.glob("*/result.json")):
        entry = load_json(result)
        if entry is None:
            continue
        digest = entry.get("engine_sha256")
        name = None
        for part in result.parent.name.split("-run"):
            name = part
            break
        by_engine.setdefault(name, set()).add(digest)
    header = {
        engine["name"]: engine.get("binary_sha256")
        for engine in doc.get("engines", [])
    }
    for name, digests in by_engine.items():
        check(
            len(digests) == 1,
            f"{path}: engine {name} ran {len(digests)} different binaries",
        )
        if name in header:
            check(
                header[name] in digests,
                f"{path}: engine {name} header digest disagrees with its repeats",
            )


def cell_samples(cell, engine, metric):
    """Per-repeat samples for one engine and metric, as the renderer reads them."""
    if cell is None:
        return []
    for entry in cell.get("engines", []):
        if entry.get("name") != engine:
            continue
        out = []
        for run in entry.get("runs", []):
            value = run.get(metric)
            if metric == "latency_us":
                if isinstance(value, dict):
                    value = value.get("median")
                else:
                    continue
            if isinstance(value, (int, float)):
                out.append(value)
        return out
    return []


def check_spread(results, cells):
    """Every cell's repeat spread is present and re-derived from its runs."""
    keys = ("n", "min", "median", "max", "mean", "stdev", "cv", "ratio",
            "gap_ratio", "state")
    for scenario in results.get("scenarios", []):
        cell = cells.get(scenario["id"])
        expected = {}
        if cell is not None:
            for entry in cell.get("engines", []):
                engine = entry.get("name")
                samples = cell_samples(cell, engine, "throughput_mib_s")
                stats = benchstats.spread(samples) if samples else None
                if stats is not None:
                    expected[engine] = stats
        reported = scenario.get("spread", {})
        if not isinstance(reported, dict):
            fail(f"{scenario['id']}/spread is not an object")
            continue
        for engine, stats in expected.items():
            if engine not in reported:
                fail(
                    f"{scenario['id']}/{engine}/spread is missing but its "
                    "throughput samples re-derive one"
                )
                continue
            if not isinstance(reported[engine], dict):
                fail(f"{scenario['id']}/{engine}/spread is not an object")
                continue
            for key in keys:
                check(
                    reported[engine].get(key) == stats.get(key),
                    f"{scenario['id']}/{engine}/spread {key} "
                    f"{reported[engine].get(key)} re-derives to {stats.get(key)}",
                )
        for engine, stats in reported.items():
            if engine not in expected:
                check(
                    stats is None,
                    f"{scenario['id']}/{engine}/spread is reported but no "
                    "throughput samples re-derive it",
                )


def expected_medians(cell):
    """The medians the renderer would derive from one cell, by engine."""
    expected = {}
    if cell is None:
        return expected
    for entry in cell.get("engines", []):
        name = entry.get("name")
        values = {}
        for metric in MEDIAN_METRICS:
            samples = cell_samples(cell, name, metric)
            if samples:
                values[metric] = benchstats.median(samples)
        latency = cell_samples(cell, name, "latency_us")
        if latency:
            values["latency_us"] = benchstats.median(latency)
        if values:
            expected[name] = values
    return expected


def check_medians(results, cells):
    """Every plotted median is present and re-derived from its repeats."""
    for scenario in results.get("scenarios", []):
        cell = cells.get(scenario["id"])
        reported = scenario.get("medians", {})
        if not isinstance(reported, dict):
            fail(f"{scenario['id']}/medians is not an object")
            continue
        expected = expected_medians(cell)
        for engine, values in expected.items():
            entry = reported.get(engine)
            if not isinstance(entry, dict):
                fail(f"{scenario['id']}/{engine}: medians are missing")
                continue
            for metric, median in values.items():
                check(
                    entry.get(metric) == median,
                    f"{scenario['id']}/{engine}/{metric}: median "
                    f"{entry.get(metric)} re-derives to {median}",
                )
            extra = set(entry) - set(values)
            check(
                not extra,
                f"{scenario['id']}/{engine}: reported medians {sorted(extra)} "
                "have no cell samples",
            )
        for engine in set(reported) - set(expected):
            fail(
                f"{scenario['id']}/{engine}: medians are reported but the cell "
                "has no samples to re-derive them"
            )


def check_manifest(results, cells):
    """Manifest engine digests match every cell header that names them."""
    headers = {}
    for scenario, cell in cells.items():
        if cell is None:
            continue
        for engine in cell.get("engines", []):
            if engine.get("binary_sha256"):
                headers.setdefault(engine.get("name"), set()).add(
                    engine["binary_sha256"]
                )
    manifest = results.get("manifest", [])
    for line in manifest:
        if not line.startswith("engine "):
            continue
        parts = line.split()
        label = parts[1].rstrip(":") if len(parts) > 1 else "?"
        digest = None
        for part in parts[2:]:
            if part.startswith("sha256="):
                digest = part.split("=", 1)[1]
        check(bool(digest), f"manifest line without digest: {line}")
        if not digest or label not in headers:
            continue
        check(
            headers[label] == {digest},
            f"manifest engine {label} digest {digest} disagrees with the "
            f"cell headers {sorted(headers[label])}",
        )


def manifest_has_binary_sizes(results):
    """True when the manifest gives an engine a size the chart can draw."""
    for line in results.get("manifest", []):
        parts = line.split()
        if len(parts) > 1 and parts[0] == "engine":
            if parts[1].rstrip(":") not in THROUGHPUT_ENGINES:
                continue
            if any(part.startswith("mib=") and part.partition("=")[2]
                   for part in parts[2:]):
                return True
    return False


def any_metric(cells, metric):
    """True when a renderer engine in any cell holds a sample it can plot."""
    return any(
        cell_samples(cell, engine.get("name"), metric)
        for cell in cells
        for engine in cell.get("engines", [])
        if engine.get("name") in THROUGHPUT_ENGINES
    )


def wanted_charts(results, cells):
    """The charts the renderer draws from these results and cells."""
    scenarios = results.get("scenarios", [])
    usable = {
        scenario["id"]: cells[scenario["id"]]
        for scenario in scenarios
        if cells.get(scenario["id"]) is not None
    }
    bulk = [
        usable[scenario["id"]] for scenario in scenarios
        if "setup" not in scenario.get("id", "")
        and scenario["id"] in usable
    ]
    priced = [
        usable[scenario["id"]] for scenario in scenarios
        if "setup" not in scenario.get("id", "")
        and scenario.get("workload", {}).get("traffic")
        in ("upload", "download", "full-duplex")
        and scenario["id"] in usable
    ]
    wanted = []
    if any_metric(bulk, "rss_mib"):
        wanted.append("memory-rss.png")
    if any_metric(bulk, "threads_peak"):
        wanted.append("threads.png")
    if any_metric(usable.values(), "startup_seconds"):
        wanted.append("startup.png")
    if any_metric(priced, "cpu_millis_per_gib"):
        wanted.append("cpu-per-gib.png")
    if any(
        any(isinstance(value, (int, float)) and value > 0
            for value in cell.get("harness_ceilings_mib_s", []))
        and any_metric([cell], "throughput_mib_s")
        for cell in priced
    ):
        wanted.append("ceiling.png")
    if manifest_has_binary_sizes(results):
        wanted.append("binary-size.png")
    if any("setup" in scenario.get("id", "") for scenario in scenarios):
        wanted.append(SETUP_CHART)
    return wanted


def check_charts(charts_dir, results, cells):
    """Every chart the bundle should hold exists and is non-empty.

    The set follows the renderer: a chart exists only when a cell holds the
    samples it draws, so a filtered or failed run does not demand an empty plot.
    """
    scenarios = results.get("scenarios", [])
    for name in wanted_charts(results, cells):
        path = Path(charts_dir) / name
        check(path.is_file(), f"missing chart {path}")
        if path.is_file():
            check(path.stat().st_size > 0, f"empty chart {path}")
    measured = {
        scenario.get("base", scenario["id"])
        for scenario in scenarios
        if scenario.get("medians")
    }
    for base in measured:
        path = Path(charts_dir) / "scenarios" / f"{base}.png"
        check(path.is_file(), f"missing per-test scenario chart {path}")
        if path.is_file():
            check(path.stat().st_size > 0, f"empty chart {path}")


def runner_block(section, runner):
    """The README block for one runner, without the other runners' rows."""
    marker = f"<!-- runner:{runner} -->"
    start = section.find(marker)
    if start == -1:
        return None
    start += len(marker)
    end = section.find("<!-- runner:", start)
    return section[start:] if end == -1 else section[start:end]


def readme_row(section, base, server):
    """The throughput row for one test, parsed into raw pipe-separated cells."""
    prefix = f"| `{base}` | {server} |"
    for line in section.splitlines():
        if line.startswith(prefix):
            return line.split("|")[1:-1]
    return None


def readme_number(cell):
    """A rendered throughput cell as an integer, or None for a gap label."""
    text = cell.strip().replace("*", "").replace(",", "").strip()
    try:
        return round(float(text))
    except ValueError:
        return None


def check_readme(readme_path, charts_dir, results):
    """README tables match matrix-results.json medians, all five engines."""
    try:
        text = Path(readme_path).read_text()
    except OSError as exc:
        fail(f"unreadable README {readme_path}: {exc}")
        return
    start = "<!-- benchmark-matrix:start -->"
    end = "<!-- benchmark-matrix:end -->"
    if start not in text or end not in text:
        fail("README has no benchmark-matrix markers")
        return
    section = text.split(start)[1].split(end)[0]
    runner = results.get("runner", "?")
    block = runner_block(section, runner)
    if block is None:
        fail(f"README has no block for runner {runner}")
        return
    seen = set()
    for scenario in results.get("scenarios", []):
        seen.update(scenario.get("medians", {}))
        seen.update(
            item.get("engine") for item in scenario.get("skipped", [])
            if item.get("engine")
        )
        seen.update(
            item.get("engine") for item in scenario.get("failures", [])
            if item.get("engine")
        )
    engines = [name for name in THROUGHPUT_ENGINES if name in seen]
    engines += sorted(seen - set(engines))
    measured = {
        scenario.get("base", scenario["id"])
        for scenario in results.get("scenarios", [])
        if scenario.get("medians")
    }
    for base in measured:
        image = f"scenarios/{base}.png"
        check(image in block, f"README has no per-test chart for {base}")
    for scenario in results.get("scenarios", []):
        if "setup" in scenario.get("id", ""):
            continue
        medians = scenario.get("medians", {})
        base = scenario.get("base", scenario["id"])
        server = scenario.get("server") or "\u2014"
        row = readme_row(block, base, server)
        if row is None:
            fail(f"README has no throughput row for {scenario['id']}")
            continue
        values = row[2:2 + len(engines)]
        check(
            len(values) == len(engines),
            f"README row for {scenario['id']} has {len(values)} engine "
            f"column(s), expected {len(engines)}",
        )
        for engine, raw in zip(engines, values, strict=False):
            value = medians.get(engine, {}).get("throughput_mib_s")
            number = readme_number(raw)
            expected = None if value is None else round(value)
            check(
                number == expected,
                f"README row for {scenario['id']}/{engine} prints {raw!r} "
                f"but matrix-results.json re-derives {expected}",
            )
    check("## Coverage" in block, "README has no coverage table section")
    check("| scenario | server |" in block, "README has no coverage table header")


def check_bundle_readme(path, results):
    """The bundle's own document names every measured test and every plot."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        fail(f"unreadable bundle document {path}: {exc}")
        return
    check("## Coverage" in text, "bundle document has no coverage table")
    check("| scenario | server |" in text, "bundle document has no coverage header")
    measured = {
        scenario.get("base", scenario["id"])
        for scenario in results.get("scenarios", [])
        if scenario.get("medians")
    }
    for base in measured:
        check(
            f"scenarios/{base}.png" in text,
            f"bundle document has no chart for {base}",
        )


def selftest():
    """Every chart the renderer omits is also not demanded here."""
    global failures
    charts = ("cpu-per-gib.png", "memory-rss.png", "threads.png",
              "startup.png", "ceiling.png", "binary-size.png")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scenarios").mkdir()
        for name in (*charts, "scenarios/x.png"):
            (root / name).write_bytes(b"png")
        results = {
            "manifest": ["engine ferrox: /x mib=10"],
            "scenarios": [{
                "id": "x", "base": "x", "workload": {"traffic": "upload"},
                "ceilings_mib_s": [100],
                "medians": {"ferrox": {"throughput_mib_s": 50}},
            }],
        }
        cells = {"x": {
            "scenario": "x", "workload": {"traffic": "upload"},
            "harness_ceilings_mib_s": [100],
            "engines": [{"name": "ferrox", "runs": [{
                "throughput_mib_s": 50,
                "cpu_millis_per_gib": 10,
                "rss_mib": 100,
                "threads_peak": 4,
                "startup_seconds": 0.1,
            }]}],
        }}
        assert set(wanted_charts(results, cells)) == set(charts)
        failures = []
        check_charts(root, results, cells)
        assert not failures, failures
        (root / "startup.png").unlink()
        failures = []
        check_charts(root, results, cells)
        assert any("missing chart" in failure for failure in failures), failures
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scenarios").mkdir()
        results = {
            "manifest": ["engine local-xray: /x mib=10"],
            "scenarios": [{
                "id": "x", "base": "x", "workload": {"traffic": "upload"},
                "ceilings_mib_s": [100], "medians": {},
            }],
        }
        cells = {"x": {
            "scenario": "x", "workload": {"traffic": "upload"},
            "harness_ceilings_mib_s": [100],
            "engines": [
                {"name": "ferrox", "runs": []},
                {"name": "local-xray", "runs": [{
                    "throughput_mib_s": 50,
                    "cpu_millis_per_gib": 10,
                    "rss_mib": 100,
                    "threads_peak": 4,
                    "startup_seconds": 0.1,
                }]},
            ],
        }}
        assert wanted_charts(results, cells) == []
        failures = []
        check_charts(root, results, cells)
        assert not failures, failures
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scenarios").mkdir()
        results = {"scenarios": [{
            "id": "x", "base": "x", "workload": {"traffic": "upload"},
        }]}
        assert wanted_charts(results, {"x": None}) == []
        failures = []
        check_charts(root, results, {"x": None})
        assert not failures, failures
    failures = []
    check_manifest({"manifest": ["engine xray-core: /x sha256="]},
                   {"s": {"engines": [{"name": "xray-core",
                                      "binary_sha256": "abc"}]}})
    assert any("without digest" in failure for failure in failures), failures
    failures = []
    check_manifest({"manifest": ["engine xray-core: /x sha256=abc"]},
                   {"s": {"engines": [{"name": "xray-core",
                                      "binary_sha256": "def"}]}})
    assert any("disagrees" in failure for failure in failures), failures
    print("validate-benchmark-matrix: selftest ok")
    return 0


def main(argv=None):
    """Validate a rendered matrix bundle."""
    global args
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(description="validate benchmark matrix bundle")
    parser.add_argument("--cells", required=True, help="cells/ directory")
    parser.add_argument("--results", required=True, help="matrix-results.json path")
    parser.add_argument("--charts", required=True, help="charts directory")
    parser.add_argument("--readme", default=None, help="README path to cross-check")
    parser.add_argument("--bundle-readme", default=None, help="bundle README path to check")
    args = parser.parse_args(argv)

    results_doc = load_json(args.results)
    if results_doc is None:
        print("\n".join(failures))
        return 1
    missing = REQUIRED_RESULTS_KEYS - set(results_doc)
    check(not missing, f"matrix-results.json missing keys {sorted(missing)}")
    reported = [scenario.get("id") for scenario in results_doc.get("scenarios", [])]
    check(
        len(reported) == len(set(reported)),
        "matrix-results.json repeats a scenario id",
    )
    on_disk = {
        path.parent.name
        for path in Path(args.cells).glob("*/cell.json")
    }
    check(
        set(reported) == on_disk,
        "matrix-results.json scenario inventory disagrees with the cells "
        f"directory (missing {sorted(on_disk - set(reported))}, "
        f"extra {sorted(set(reported) - on_disk)})",
    )
    cells = {}
    for scenario in results_doc.get("scenarios", []):
        cell = check_cell(Path(args.cells) / scenario["id"] / "cell.json")
        cells[scenario["id"]] = cell
        if cell is not None:
            check(
                cell.get("scenario") == scenario["id"],
                f"cell scenario {cell.get('scenario')} filed under {scenario['id']}",
            )
            ran = any(
                engine.get("runs")
                for engine in cell.get("engines", [])
            )
            throughput = (
                cell.get("workload", {}).get("traffic")
                in ("upload", "download", "full-duplex")
            )
            check(
                not ran or cell.get("harness_ceilings_mib_s") or not throughput,
                f"{scenario['id']}: engines ran but no harness ceiling was recorded",
            )
    check_spread(results_doc, cells)
    check_medians(results_doc, cells)
    check_manifest(results_doc, cells)
    check_charts(args.charts, results_doc, cells)
    if args.readme:
        check_readme(args.readme, args.charts, results_doc)
    if args.bundle_readme:
        check_bundle_readme(args.bundle_readme, results_doc)
    if failures:
        print("\n".join(failures))
        return 1
    print(
        f"matrix valid: {len(results_doc.get('scenarios', []))} scenarios"
        + (", README consistent" if args.readme else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
