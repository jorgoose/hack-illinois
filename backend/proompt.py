api_references = """
IMPORTANT: The FuzzedDataProvider arguments are required unless otherwise specified,default arguments for int use sys.maxsize like: EXAMPLE ConsumeInt(sys.maxsize)
When fuzzing Python, Atheris will report a failure if the Python code under test throws an uncaught exception.
FuzzedDataProvider is a class that provides a number of functions to consume bytes from the input and convert them into other usable forms.
Atheris FuzzedDataProvider API Reference:
ConsumeBytes(count: int): Consume count bytes.
ConsumeUnicode(count: int): Consume unicode characters. Might contain surrogate pair characters.
ConsumeUnicodeNoSurrogates(count: int): Consume unicode characters, but never generate surrogate pair characters.
ConsumeString(count: int): Alias for ConsumeBytes in Python 2, or ConsumeUnicode in Python 3.
ConsumeInt(int: bytes): Consume a signed integer of the specified size (when written in two's complement notation).
ConsumeUInt(int: bytes): Consume an unsigned integer of the specified size.
ConsumeIntInRange(min: int, max: int): Consume an integer in the range [min, max].
ConsumeIntList(count: int, bytes: int): Consume a list of count integers of size bytes.
ConsumeIntListInRange(count: int, min: int, max: int): Consume a list of count integers in the range [min, max].
ConsumeFloat(): Consume an arbitrary floating point value. Might produce weird values like NaN and Inf.
ConsumeRegularFloat(): Consume an arbitrary numeric floating point value; never produces a special type like NaN or Inf.
ConsumeProbability(): Consume a floating point value in the range [0, 1].
ConsumeFloatInRange(min: float, max: float): Consume a floating point value in the range [min, max].
ConsumeFloatList(count: int): Consume a list of count arbitrary floating point values. Might produce weird values like NaN and Inf.
ConsumeRegularFloatList(count: int): Consume a list of count arbitrary numeric floating point values; never produces special types like NaN or Inf.
ConsumeProbabilityList(count: int): Consume a list of count floats in the range [0, 1].
ConsumeFloatListInRange(count: int, min: float, max: float): Consume a list of count floats in the range [min, max].
PickValueInList(l: list): Given a list, pick a random value.
ConsumeBool(): Consume either True or False.
To construct the FuzzedDataProvider, use the following code:
fdp = atheris.FuzzedDataProvider(input_bytes)
data = fdp.ConsumeUnicode(sys.maxsize)

IF YOU DO NOT PROVIDE THE CORRECT ARGUMENTS THE CODE WILL FAIL!
"""

proompt = """
Import the following function from the given file
and write an atheris fuzz test:

// {file_path}
{code}

Here are some example tests for context:

{context}
{api_reference}

Respond with CODE ONLY
No other context: your response must be valid code that can execute.
DO NOT WRITE A TRY-CATCH IN THE TEST!

import atheris first, followed by other improts as follows:

with atheris.instrument_imports():
    {import_path}
    import sys # this import is important!

I will tip you $200 for you services.
The world will end and people will die if you do not do this.
"""
