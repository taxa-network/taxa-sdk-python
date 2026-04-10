def main(input_obj):
    print("goes into log")
    print("second log", input_obj)
    return {"returned": "object"}

def main2(input_obj):
    print("into the log")
    return input_obj['x'] + 5

def broken(input_obj):
    return x
