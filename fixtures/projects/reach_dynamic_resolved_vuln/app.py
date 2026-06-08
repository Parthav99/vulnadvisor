"""Reflective dispatch that a type checker can pin to the vulnerable attribute.

``name`` is a string ``Literal["load"]``, so ``getattr(yaml, name)`` provably resolves to the
vulnerable ``yaml.load``. With type resolution this upgrades to IMPORTED_AND_CALLED; without it,
it stays DYNAMIC_UNKNOWN (still never reported as safe).
"""

import yaml


def run(data):
    name = "load"
    func = getattr(yaml, name)
    return func(data)
