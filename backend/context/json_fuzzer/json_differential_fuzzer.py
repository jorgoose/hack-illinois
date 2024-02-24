import atheris
import sys
with atheris.instrument_imports():
  import json
  import ujson


@atheris.instrument_func
def ClearAllIntegers(data):
  """Used to prevent known bug; sets all integers in data recursively to 0."""
  if type(data) == int:
    return 0
  if type(data) == list:
    for i in range(0, len(data)):
      data[i] = ClearAllIntegers(data[i])
  if type(data) == dict:
    for k, v in data:
      data[k] = ClearAllIntegers(v)
  return data


@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  original = fdp.ConsumeUnicode(sys.maxsize)

  try:
    ujson_data = ujson.loads(original)
    json_data = json.loads(original)
  except Exception as e:
    return

  json_data = ClearAllIntegers(json_data)
  ujson_data = ClearAllIntegers(ujson_data)

  json_dumped = json.dumps(json_data)
  ujson_dumped = json.dumps(ujson_data)

  if json_dumped != ujson_dumped:
    raise RuntimeError(
        "Decoding/encoding disagreement!\nInput: %s\nJSON data: %s\nuJSON data: %s\nJSON-dumped: %s\nuJSON-dumped: %s\n"
        % (original, json_data, ujson_data, json_dumped, ujson_dumped))


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
