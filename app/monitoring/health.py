import psutil
import platform


def system_health():

    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "python_version": platform.python_version(),
        "system": platform.system(),
        "status": "healthy",
    }
