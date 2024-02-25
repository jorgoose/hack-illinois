from lambda_function import lambda_handler
import json


def main():
    body = {
        "repo": "https://github.com/kygoben/ultra-secure-python-code.git",
        "local": True,
        "repo_name": "ultra-secure-python-code"
    }

    event = {
        "headers": {},
        "body": json.dumps(body)
    }
    lambda_handler(event, 0)


if __name__ == "__main__":
    main()
