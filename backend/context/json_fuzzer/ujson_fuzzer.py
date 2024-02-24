import sys
import atheris

import ujson


def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  original = fdp.ConsumeUnicode(sys.maxsize)

  try:
    ujson_data = ujson.loads(original)
  except ValueError:
    return

  encoded = ujson.dumps(ujson_data)
  del encoded


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
