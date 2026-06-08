import importlib


def test_package_imports() -> None:
    module = importlib.import_module("vulnadvisor")
    assert module.__doc__ is not None
