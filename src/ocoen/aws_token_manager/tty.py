import functools
# Importing readline makes input behave nicer (e.g. backspace works) so not actually unused
import readline  # NOQA
import sys

from contextlib import contextmanager
from io import TextIOWrapper


def if_tty(**kwargs):
    return tty_conditional(tty_desired=True, **kwargs)


def if_not_tty(**kwargs):
    return tty_conditional(tty_desired=False, **kwargs)


def tty_conditional(tty_desired=True, prompt=None, default_return=None, streams=[sys.stdout]):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            streams_are_tty = not next((s for s in streams if not s.isatty()), False)
            if streams_are_tty == tty_desired:
                return func(*args, **kwargs)
            else:
                if prompt:
                    with tty():
                        resp = input(prompt)
                    if resp and resp.upper()[0] == 'Y':
                        return func(*args, **kwargs)
            return default_return
        return wrapper
    return decorator


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
