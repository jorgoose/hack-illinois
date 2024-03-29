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


def test_walker(tests, target_dir, the_dir):
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

        interesting_output[test] = {
            "stdout": str(output),
            "stderr": str(err),
            "ran": True
        }

    coverage_dir = f'{the_dir}/coverage'
    tests_dir = f'{the_dir}/tests'
    crashes_dir = f'{the_dir}/crashes'

    os.mkdir(coverage_dir)
    os.mkdir(tests_dir)
    os.mkdir(crashes_dir)

    with open(f"{the_dir}/results.json", "w") as file:
        json.dump(interesting_output, file, indent=4)
    for cov_file in Path(target_dir).rglob(".coverage*"):
        shutil.move(cov_file, coverage_dir)
    subprocess.Popen(["coverage", "combine"], cwd=coverage_dir).wait()
    subprocess.Popen(["coverage", "html"], cwd=coverage_dir).wait()
    for fuzz in Path(target_dir).rglob('*fuzz-guard.py'):
        shutil.move(fuzz, tests_dir)
    for crash in os.listdir('.'):
        if "crash-" in crash:
            shutil.move(crash, crashes_dir)
