"""Development-environment diagnostics."""

import sys
from pathlib import Path


def get_environment_details() -> dict[str, str]:
    """Return information about the active Python environment."""
    project_root = Path(__file__).resolve().parent.parent

    return {
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "project_root": str(project_root),
    }


def main() -> None:
    """Print development-environment information."""
    details = get_environment_details()

    for name, value in details.items():
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()
