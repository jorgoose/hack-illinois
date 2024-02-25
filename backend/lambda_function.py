import ast
import json
import os
from openai import OpenAI
# from dotenv import load_dotenv
from proompt import proompt, api_references
from pathlib import Path
from test_walker import test_walker
import subprocess

# load_dotenv()

client = OpenAI(api_key=os.getenv("OPEN_AI_API_KEY"))


def ask_chatgpt(prompt):
    try:
        response = client.chat.completions.create(
            messages=[{
                "role": "user",
                "content": prompt
            }],
            model="gpt-3.5-turbo"
            # model="gpt-4"
        )
        response = response.choices[0].message.content
        return response
    except Exception as e:
        print("Error:", e)
        return None


def read_files_in_directory(directory_path):
    file_contents = []
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            with open(file_path, "r") as file:
                file_contents.append(f"#{file_name}\n{file.read()}")
    return file_contents


def get_functions(file_path):
    functions = []

    with open(file_path, "r") as file:
        code = file.read()

    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            function_name = node.name
            function_text = ast.get_source_segment(code, node)
            functions.append((function_name, function_text))

    return functions


def write_to_file(path, contents):
    try:
        directory_path = os.path.dirname(path)

        if not os.path.exists(directory_path):
            os.makedirs(directory_path)

        with open(path, "w") as file:
            file.write(contents)

    except Exception as e:
        print(f"Error occurred while writing to '{path}': {e}")


def parse_markdown_wrapping(text):
    lines = text.split('\n')

    if lines and '`' in lines[0]:
        lines.pop(0)
    if lines and '`' in lines[-1]:
        lines.pop(-1)

    return '\n'.join(lines)


def main(TARGET_DIR, the_dir):
    targets = {}
    tests = []
    for py_file in Path(TARGET_DIR).rglob("*.py"):
        functions = get_functions(py_file)
        targets[str(py_file)] = functions

    context = read_files_in_directory("context")
    context = "\n".join(context)

    for path, data in targets.items():
        for function_name, function in data:
            import_path = f"from {os.path.basename(path).split('.')[0]} import {function_name}"
            message = proompt.format(
                code=function,
                file_path=path,
                context=context,
                api_reference=api_references,
                import_path=import_path
            )
            response = ask_chatgpt(message)
            test_path = f"{path}.{function_name}.fuzz-guard.py"
            tests.append(test_path)
            write_to_file(test_path, parse_markdown_wrapping(response))
    test_walker(tests, TARGET_DIR, the_dir)


def print_all_files(folder_path):
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            print(full_path)


def lambda_handler(event, context):
    body = event["body"]
    body = json.loads(body)
    repo = body["repo"]
    repo_name = body["repo_name"]
    local = body["local"]

    if local:
        the_dir = "../chris"
    else:
        the_dir = "/tmp"

    subprocess.call(["git", "clone", repo], cwd=the_dir)

    main(f"{the_dir}/{repo_name}", the_dir)
    print_all_files(the_dir)
