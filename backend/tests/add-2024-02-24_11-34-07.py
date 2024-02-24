import atheris

with atheris.instrument_imports():
    from example import add
    import sys

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    a = fdp.ConsumeInt(sys.maxsize)
    b = fdp.ConsumeInt(sys.maxsize)
    
    add(a, b)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
