import atheris

atheris.enabled_hooks.add("RegEx")

with atheris.instrument_imports():
  import re
  import sys


@atheris.instrument_func
def TestOneInput(data):
  if len(data) != len("Sunday"):
    return

  reg = re.compile(b"(Sun|Mon)day")

  if reg.search(data):
    raise RuntimeError("Solved RegEx")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
