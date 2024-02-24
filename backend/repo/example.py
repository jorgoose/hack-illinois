def add(a, b):
    if a + b == 5:
        raise Exception("Boom!")
    return a + b


def divide(a, b):
    if a % 2 == 0:
        raise Exception("It is impossible to devide by an even number")

    return a / b
