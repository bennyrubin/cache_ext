"""OpenEvolve evaluator for the cache_ext file-search benchmark."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple

try:
    from openevolve.evaluation_result import EvaluationResult
except ImportError:  # allow running outside OpenEvolve
    class EvaluationResult:  # type: ignore
        def __init__(self, metrics, artifacts):
            self.metrics = metrics
            self.artifacts = artifacts

        def __repr__(self) -> str:
            return f"EvaluationResult(metrics={self.metrics}, artifacts={self.artifacts})"


REPO_ROOT = Path.home() / "cache_ext"
FILESEARCH_DIR = REPO_ROOT / "eval" / "filesearch"
RESULTS_DIR = REPO_ROOT / "results"
POLICY_DEST = REPO_ROOT / "policies" / "cache_ext_agent.bpf.c"
BUILD_SCRIPT = REPO_ROOT / "build_policies.sh"


def _run_filesearch_script(results_filename: str) -> Dict[str, str]:
    """Execute eval/filesearch/run.sh and capture stdout/stderr live."""
    print(f"[evaluator] Running {FILESEARCH_DIR / 'run.sh'} ...")
    artifacts: Dict[str, str] = {}
    script = FILESEARCH_DIR / "run.sh"
    if not script.exists():
        msg = f"run.sh not found at {script}"
        print(f"[evaluator] {msg}")
        artifacts["run_error"] = msg
        return artifacts

    try:
        process = subprocess.Popen(
            ["bash", str(script), results_filename],
            cwd=FILESEARCH_DIR,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )
    except Exception as exc:  # pragma: no cover - defensive
        msg = f"Failed to execute run.sh: {exc}"
        print(f"[evaluator] {msg}")
        artifacts["run_error"] = msg
        return artifacts

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    def _stream(pipe, buffer, label):
        assert pipe is not None
        for line in pipe:
            print(f"[evaluator] {label}: {line.rstrip()}")
            buffer.append(line)
        pipe.close()

    threads = [
        threading.Thread(target=_stream, args=(process.stdout, stdout_lines, "stdout"), daemon=True),
        threading.Thread(target=_stream, args=(process.stderr, stderr_lines, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    returncode = process.wait()
    for thread in threads:
        thread.join()

    print(f"[evaluator] run.sh exit code: {returncode}")

    artifacts["run_stdout"] = "".join(stdout_lines)
    artifacts["run_stderr"] = "".join(stderr_lines)
    artifacts["run_exit_code"] = str(returncode)
    artifacts["results_filename"] = results_filename
    return artifacts


def _load_cache_ext_runtimes(path: Path) -> List[float]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []

    runtimes: List[float] = []
    for entry in data if isinstance(data, list) else []:
        config = entry.get("config", {})
        if config.get("cgroup_name") != "cache_ext_test":
            continue
        try:
            runtimes.append(float(entry.get("results", {}).get("runtime_sec")))
        except (TypeError, ValueError):
            continue
    return runtimes


def _prepare_policy(program_path: str | None) -> Tuple[bool, Dict[str, str]]:
    artifacts: Dict[str, str] = {}
    if program_path is None:
        return True, artifacts

    candidate = str(program_path).strip()
    if not candidate:
        return True, artifacts

    source_path = Path(candidate).expanduser()
    if not source_path.exists() or not source_path.is_file():
        msg = f"Provided program_path does not exist or is not a file: {source_path}"
        print(f"[evaluator] {msg}")
        artifacts["program_error"] = msg
        return False, artifacts

    if source_path.suffix != ".c":
        msg = f"Expected a BPF C source (.c), got: {source_path}"
        print(f"[evaluator] {msg}")
        artifacts["program_error"] = msg
        return False, artifacts

    source_real = source_path.resolve()
    dest_real = POLICY_DEST.resolve()
    if source_real != dest_real:
        try:
            shutil.copyfile(source_real, dest_real)
        except OSError as exc:
            msg = f"Failed to copy BPF program to {POLICY_DEST}: {exc}"
            print(f"[evaluator] {msg}")
            artifacts["program_error"] = msg
            return False, artifacts
        artifacts["copied_policy_from"] = str(source_real)
    else:
        print("[evaluator] program_path already points to the active cache_ext_agent.bpf.c; skipping copy.")

    if not BUILD_SCRIPT.exists():
        msg = f"build_policies.sh not found at {BUILD_SCRIPT}"
        print(f"[evaluator] {msg}")
        artifacts["build_error"] = msg
        return False, artifacts

    print(f"[evaluator] Running {BUILD_SCRIPT} to rebuild policies ...")
    build_proc = subprocess.run(
        ["bash", str(BUILD_SCRIPT)],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )
    artifacts["build_stdout"] = build_proc.stdout
    artifacts["build_stderr"] = build_proc.stderr
    artifacts["build_exit_code"] = str(build_proc.returncode)

    if build_proc.returncode != 0:
        msg = f"build_policies.sh failed with exit code {build_proc.returncode}"
        print(f"[evaluator] {msg}")
        artifacts["build_error"] = msg
        return False, artifacts

    return True, artifacts


def evaluate(program_path: str | None = None) -> EvaluationResult:
    """Run the file-search benchmark and report cache_ext runtimes."""
    metrics: Dict[str, float] = {
        "cache_ext_avg_runtime_sec": 0.0,
        "cache_ext_run_count": 0.0,
        "combined_score": 0.0,
    }
    artifacts: Dict[str, str] = {}

    success, prep_artifacts = _prepare_policy(program_path)
    artifacts.update(prep_artifacts)
    if not success:
        metrics["combined_score"] = float("-inf")
        return EvaluationResult(metrics=metrics, artifacts=artifacts)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_filename = f"filesearch_results_{timestamp}.json"
    results_path = RESULTS_DIR / results_filename

    run_artifacts = _run_filesearch_script(results_filename)
    artifacts.update(run_artifacts)

    print("[evaluator] Parsing cache_ext runtimes ...")
    runtimes = _load_cache_ext_runtimes(results_path)
    if runtimes:
        avg_runtime = mean(runtimes)
        metrics["cache_ext_avg_runtime_sec"] = avg_runtime
        metrics["cache_ext_run_count"] = float(len(runtimes))
        metrics["combined_score"] = -avg_runtime
        print(
            f"[evaluator] Found {len(runtimes)} cache_ext runs; "
            f"avg runtime = {metrics['cache_ext_avg_runtime_sec']:.3f}s"
        )
    else:
        print("[evaluator] No cache_ext runs found in results file.")
        metrics["combined_score"] = float("-inf")

    return EvaluationResult(metrics=metrics, artifacts=artifacts)


if __name__ == "__main__":
    print(evaluate())
