"""Minimal multipart/form-data parser (the stdlib ``cgi`` module is gone in
Python 3.13+).

Only what the webservice needs is implemented: named text fields and file
uploads, exposed as ``FieldStorage`` with a dict-like ``__getitem__`` /
``__contains__``.  File parts get a ``.file`` (BytesIO) and ``.filename``;
text parts get ``.value``.
"""

import io
import re

_MAX_BODY = 512 * 1024 * 1024


class Field:
    def __init__(self, name, body, filename=None):
        self.name = name
        self.filename = filename
        self.file = io.BytesIO(body)
        self.value = body.decode("utf-8", "replace")


class FieldStorage:
    def __init__(self, fp=None, headers=None, environ=None, **_kwargs):
        headers = headers or {}
        environ = environ or {}
        content_type = (headers.get("Content-Type") or
                        environ.get("CONTENT_TYPE") or "")
        try:
            length = int(headers.get("Content-Length") or
                         environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0 or length > _MAX_BODY:
            self.fields = {}
            return
        match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
        if not match:
            self.fields = {}
            return
        boundary = (match.group(1) or match.group(2)).strip()
        raw = fp.read(length)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        self.fields = self._parse(raw, boundary)

    @staticmethod
    def _parse(raw, boundary):
        fields = {}
        delimiter = b"--" + boundary.encode("ascii")
        for chunk in raw.split(delimiter):
            if not chunk or chunk in (b"--", b"--\r\n"):
                continue
            if chunk.startswith(b"\r\n"):
                chunk = chunk[2:]
            if chunk.endswith(b"\r\n"):
                chunk = chunk[:-2]
            head, sep, body = chunk.partition(b"\r\n\r\n")
            if not sep:
                continue
            disposition = ""
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-disposition:"):
                    disposition = line.decode("utf-8", "replace")
                    break
            name_match = re.search(r'name="([^"]*)"', disposition)
            if not name_match:
                continue
            filename_match = re.search(r'filename="([^"]*)"', disposition)
            filename = filename_match.group(1) if filename_match else None
            fields[name_match.group(1)] = Field(
                name_match.group(1), body, filename)
        return fields

    def __contains__(self, key):
        return key in self.fields

    def __getitem__(self, key):
        return self.fields[key]
