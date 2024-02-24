import atheris

with atheris.instrument_imports():
  import sys
  import zlib


def CustomMutator(data, max_size, seed):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    decompressed = b'Hi'
  else:
    decompressed = atheris.Mutate(decompressed, len(decompressed))
  return zlib.compress(decompressed)


@atheris.instrument_func
def TestOneInput(data):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    return

  if len(decompressed) < 2:
    return

  try:
    if decompressed.decode() == 'FU':
      raise RuntimeError('Boom')
  except UnicodeDecodeError:
    pass


if __name__ == '__main__':
  if len(sys.argv) > 1 and sys.argv[1] == '--no_mutator':
    atheris.Setup(sys.argv, TestOneInput)
  else:
    atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
  atheris.Fuzz()
