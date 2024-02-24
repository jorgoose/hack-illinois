import sys
import atheris

# Import the function from the provided file
from example import add

# Define the fuzz test function
@atheris.instrument_func
def test_add(data):
    # Construct FuzzedDataProvider
    fdp = atheris.FuzzedDataProvider(data)
    
    # Consume integers a and b
    a = fdp.ConsumeInt(sys.maxsize)
    b = fdp.ConsumeInt(sys.maxsize)
    
    # Call the add function
    try:
        add(a, b)
    except Exception:
        pass

# Setup Atheris and start fuzzing
atheris.Setup(sys.argv, test_add)
atheris.Fuzz()
