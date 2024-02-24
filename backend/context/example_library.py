def CodeBeingFuzzed(number):
  if number == 17:
    raise RuntimeError('Number was seventeen!')
