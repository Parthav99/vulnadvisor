"""Reflective dispatch that a type checker can pin to a non-vulnerable attribute.

``name`` is a string ``Literal["safe_load"]``, so ``getattr(yaml, name)`` provably resolves to
``yaml.safe_load`` — never the vulnerable ``yaml.load``. With type resolution this is IMPORTED
(false positive removed); without it, the access stays DYNAMIC_UNKNOWN (sound over-approximation).
"""

import yaml


def run(data):
    name = "safe_load"
    func = getattr(yaml, name)
    return func(data)
