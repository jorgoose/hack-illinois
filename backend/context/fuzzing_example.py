import atheris
import sys

with atheris.instrument_imports():
  import struct
  import example_library


@atheris.instrument_func
def TestOneInput(data):
  if len(data) != 4:
    return

  number, = struct.unpack('<I', data)
  example_library.CodeBeingFuzzed(number)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
