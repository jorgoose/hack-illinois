import atheris

atheris.enabled_hooks.add("str")

with atheris.instrument_imports():
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
  fdp = atheris.FuzzedDataProvider(data)
  data = fdp.ConsumeString(sys.maxsize)

  # This will be instrumented since the str startswith method is called
  # Note that this also works for the str endswith method as well
  if data.startswith("foobarbazbiz", 5, 20):
    raise RuntimeError("Solved str startswith method")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
