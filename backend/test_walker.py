import subprocess
import os
from pathlib import Path
import shutil
import json


def run_with_timeout(command, timeout_seconds):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait(timeout=timeout_seconds)
        return process.returncode, process.stdout.read().decode(), process.stderr.read().decode()
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "Process timed out", ""


def test_walker(tests):
    interesting_output = {}
    good_tests = []
    for test in tests:
        command = ["python", test]
        return_code, stdout, stderr = run_with_timeout(command, timeout_seconds=2)

        if "FuzzedDataProvider" in stdout:
            interesting_output[test] = {"stdout": stdout, "stderr": stderr, "ran": False}
        else:
            good_tests.append(test)


    for test in good_tests:
        basename = os.path.basename(test)
        dirname = os.path.dirname(test)

        command = ["python", "-m", "coverage", "run", "--parallel-mode", basename, "-atheris_runs=1000"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=dirname)
        output, err = process.communicate()

        if output != b'':
            interesting_output[test] = {
                "stdout": output,
                "stderr": err,
                "ran": True
            }

    with open("results.json", "w") as file:
        json.dump(interesting_output, file, indent=4)
    for fuzz in Path('repo').rglob('*fuzz-guard.py'):
        shutil.move(fuzz, "tests")
    for crash in os.listdir('.'):
        if "crash-" in crash:
            shutil.move(crash, "crashes")
    for cov_file in Path('repo').rglob(".coverage*"):
        shutil.move(cov_file, "coverage")
    subprocess.Popen(["coverage", "combine"], cwd="coverage")
    subprocess.Popen(["coverage", "html"], cwd="coverage")
