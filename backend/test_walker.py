import subprocess


def test_walker(tests):
    for test in tests:
        command = ["python", test]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = process.communicate()

        print("Standard Output:")
        print(output.decode())
        print("\nStandard Error:")
        print(err.decode())
