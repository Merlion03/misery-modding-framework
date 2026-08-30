#!/usr/bin/env python3
"""Byte offsets of individual fields in the probe's IO block -- computed, then
PROVED against the reader that already works.

WHY THIS IS NEEDED
------------------
The aggregate session updates a few fields of a live IO block in the game's
address space between operations: the current row's name, its texts and values,
and the asset handles a particular registration owns. Rewriting the whole block
is not an option, because most of it is output state -- the aggregate table
pointer, its store handle, the interned trigger -- that must survive from one
registration to the next.

WHY IT IS VERIFIED RATHER THAN TRUSTED
--------------------------------------
``struct.calcsize`` on a prefix of a native-alignment format is the obvious way
to get an element's offset, and it is very nearly right: the one thing it can do
wrong is add trailing padding to align the prefix as if it were a complete
struct. A silently-wrong offset here would write a row name over a table pointer.

So every offset this module hands out has been checked against a value
``cr01c5_controller.unpack_io`` independently read from the same bytes. If a
single one disagrees, nothing is returned at all -- the caller gets an exception,
not a plausible number.
"""
import re
import struct

_TOKEN = re.compile(r"(\d*)([xcbB?hHiIlLqQnNefdspP])")


def expand(fmt):
    """One entry per struct element, in order.

    ``s`` is special: ``80s`` is ONE element of 80 bytes, whereas ``128H`` is 128
    elements. Getting that backwards would shift every offset after it.
    """
    out = []
    for count, code in _TOKEN.findall(fmt):
        n = int(count) if count else 1
        if code == "s":
            out.append("%d%s" % (n, code))
        else:
            out.extend([code] * n)
    return out


def offsets(fmt):
    """Byte offset of every element of *fmt*."""
    tokens = expand(fmt)
    result, prefix = [], ""
    for token in tokens:
        result.append(struct.calcsize(prefix) if prefix else 0)
        prefix += token
    return result, tokens


class IoLayout(object):
    """Named field offsets, proved against a known-good decode."""

    def __init__(self, fmt, sample_bytes, decoded, index_of):
        self._fmt = fmt
        self._offsets, self._tokens = offsets(fmt)
        self._index_of = dict(index_of)
        self.verified = {}
        self.failures = []
        for name, index in self._index_of.items():
            if index >= len(self._offsets):
                self.failures.append((name, "element index %d out of range" % index))
                continue
            off, token = self._offsets[index], self._tokens[index]
            try:
                got = struct.unpack_from("<" + token if token in "QIH" else token,
                                         sample_bytes, off)[0]
            except Exception as exc:                           # noqa: BLE001
                self.failures.append((name, "unpack failed: %r" % exc))
                continue
            want = decoded.get(name)
            if want is None:
                self.failures.append((name, "no decoded value to check against"))
            elif got != want:
                self.failures.append(
                    (name, "offset %d reads %r but the working decoder says %r"
                     % (off, got, want)))
            else:
                self.verified[name] = {"offset": off, "token": token, "value": got}
        if self.failures:
            raise ValueError(
                "IO layout could not be proved; refusing to hand out offsets that would "
                "be written into a live process. Failures: %r" % (self.failures,))

    def offset(self, name):
        return self.verified[name]["offset"]

    def token(self, name):
        return self.verified[name]["token"]

    def as_dict(self):
        return {"verified": self.verified, "element_count": len(self._offsets)}
