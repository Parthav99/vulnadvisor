"""A concrete call path exists: main -> parse -> yaml.load."""

import yaml


def parse(data):
    return yaml.load(data)


def main():
    return parse("a: 1")


main()
