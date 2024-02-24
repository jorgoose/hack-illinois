import atheris

atheris.enabled_hooks.add("str")

with atheris.instrument_imports():
  import sys


@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  data = fdp.ConsumeString(sys.maxsize)

  if data.startswith("foobarbazbiz", 5, 20):
    raise RuntimeError("Solved str startswith method")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
