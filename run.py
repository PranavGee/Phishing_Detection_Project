"""
PhishGuard task runner — one entry point for the whole project.

    python run.py setup      install Python dependencies
    python run.py train      train and compare the models
    python run.py evaluate   metrics + all report figures
    python run.py export     export the on-device model for the extension
    python run.py verify     check the feature extractor against the dataset
    python run.py test       run the API and extension test suites
    python run.py web        start the web app on http://127.0.0.1:5000
    python run.py all        train -> evaluate -> export -> verify -> test
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def run(*args, optional=False):
    """Run a sub-command, echoing it first. Returns its exit code."""
    printable = " ".join(str(a) for a in args)
    print("\n$ " + printable, flush=True)
    code = subprocess.call(list(args), cwd=ROOT)
    if code != 0 and not optional:
        print("\nStep failed (exit " + str(code) + "): " + printable)
        raise SystemExit(code)
    return code


TASKS = {
    "setup": lambda: run(PY, "-m", "pip", "install", "-r", "requirements.txt"),
    "train": lambda: run(PY, os.path.join("ml", "train_model.py")),
    "evaluate": lambda: run(PY, os.path.join("ml", "evaluate.py")),
    "export": lambda: run(PY, os.path.join("ml", "export_js_model.py")),
    "verify": lambda: run(PY, os.path.join("ml", "verify_features.py")),
    "web": lambda: run(PY, os.path.join("webapp", "app.py")),
}


def task_test():
    run(PY, os.path.join("tests", "test_api.py"))
    if run("node", os.path.join("tests", "test_extension.js"), optional=True) != 0:
        print("\n(Extension tests need Node.js on PATH — skipped.)")
    run(PY, os.path.join("ml", "parity_check.py"), optional=True)


def task_all():
    TASKS["train"]()
    TASKS["evaluate"]()
    TASKS["export"]()
    TASKS["verify"]()
    task_test()
    print("\nDone. Start the web app with:  python run.py web")


TASKS["test"] = task_test
TASKS["all"] = task_all


def main() -> int:
    task = sys.argv[1] if len(sys.argv) > 1 else "all"
    if task not in TASKS:
        print(__doc__)
        print("Unknown task: " + task)
        return 1
    TASKS[task]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
