import platform
import sys
from pathlib import Path


def get_system_info():
    return {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "executable": sys.executable,
    }
