import atheris

atheris.enabled_hooks.add("RegEx")

with atheris.instrument_imports():
  import re
  import sys


@atheris.instrument_func  # Instrument the TestOneInput function itself
def TestOneInput(data):
  """The entry point for our fuzzer.

  This is a callback that will be repeatedly invoked with different arguments
  after Fuzz() is called.
  We translate the arbitrary byte string into a format our function being fuzzed
  can understand, then call it.

  Args:
    data: Bytestring coming from the fuzzing engine.
  """
  if len(data) != len("Sunday"):
    return

  # prefix = data[:len("Sunday")]
  reg = re.compile(b"(Sun|Mon)day")

  if reg.search(data):
    raise RuntimeError("Solved RegEx")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
