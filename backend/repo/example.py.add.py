import atheris

with atheris.instrument_imports():
    from example import add
    import sys

@atheris.instrument_func
def test_add(data):
    fdp = atheris.FuzzedDataProvider(data)
    a = fdp.ConsumeInt(sys.maxsize)
    b = fdp.ConsumeInt(sys.maxsize)

    try:
        add(a, b)
    except Exception as e:
        pass

atheris.Setup(sys.argv, test_add)
atheris.Fuzz()