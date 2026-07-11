import subprocess
import sys
from pathlib import Path

FILE_NAME = Path(Path.cwd() / 'asleep.py').as_posix()
ARGS = ['--random-country', '-t', '5000']

while True:
    subprocess.run([sys.executable, FILE_NAME, *ARGS])
