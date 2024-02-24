import atheris

with atheris.instrument_imports():
    from sub_dir.subtract import sub

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    a = fdp.ConsumeInt()
    b = fdp.ConsumeInt()
    
    result = sub(a, b)

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()