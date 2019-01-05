import functools
# Importing readline makes input behave nicer (e.g. backspace works) so not actually unused
import readline  # NOQA
import sys

from contextlib import contextmanager
from io import TextIOWrapper


def if_tty(error_message=None, default_return=None, streams=[sys.stdout, sys.stdin]):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            streams_are_tty = not next((s for s in streams if not s.isatty()), False)
            if streams_are_tty:
                return func(*args, **kwargs)
            elif error_message:
                raise RuntimeError(error_message)
            else:
                return default_return
        return wrapper
    return decorator


def if_not_tty(prompt=None, default_return=None, streams=[sys.stdout]):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            streams_are_not_tty = next((s for s in streams if not s.isatty()), False)
            if streams_are_not_tty:
                return func(*args, **kwargs)
            else:
                if prompt and confirm(prompt):
                    return func(*args, **kwargs)
            return default_return
        return wrapper
    return decorator


def confirm(prompt):
    resp = tty_input(prompt)
    return resp and resp.upper()[0] == 'Y'


def tty_input(prompt):
    with tty():
        return input(prompt)


@contextmanager
def tty():
    if sys.stdin.isatty() and sys.stdout.isatty():
        yield
    else:
        try:
            old_stdin, old_stdout = sys.stdin, sys.stdout
            with open('/dev/tty', 'r+b', buffering=False) as f:
                wrapper = TextIOWrapper(f, write_through=True)
                sys.stdin = wrapper
                sys.stdout = wrapper
                yield
        finally:
            sys.stdin, sys.stdout = old_stdin, old_stdout
