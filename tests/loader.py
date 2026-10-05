"""Les trois Lambdas s'appellent toutes handler.py : on les charge sous des noms distincts."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_lambda(name):
    spec = importlib.util.spec_from_file_location(f"adl_{name}", ROOT / "lambdas" / name / "handler.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
