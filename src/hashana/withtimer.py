from time import time

class Timer:
    description: str
    def __init__(self, description: str):
        self.description = description
    def __enter__(self):
        self.start = time()
        return self
    def __exit__(self, *args):
        elapsed = time()-self.start
        print(f"Elapsed time for {self.description}: {elapsed}")