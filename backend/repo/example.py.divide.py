import atheris

with atheris.instrument_imports():
    from example import divide
    import sys

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    a = fdp.ConsumeFloat()
    b = fdp.ConsumeFloat()
    divide(a, b)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()