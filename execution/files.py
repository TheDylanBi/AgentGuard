"""Windows local NTFS file executor with pinned handles and bounded UTF-8 I/O.

All ancestors are opened without delete/write sharing, and reparse points are
rejected. The final file is opened without data sharing. Authorization
binds identities and content; execution uses the SAME handle used for checking.
No shell, callbacks, network paths, arbitrary codecs or caller-selected flags.
Metadata-only hard-link creation is not prevented by sharing flags: deployment
must deny untrusted principals WRITE_ATTRIBUTES and resource ownership.
"""
import ctypes
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re

MAX_BYTES = 4 * 1024 * 1024


class ResourceRejected(ValueError):
    pass


def validate_action(action):
    if action.type not in ("read_file", "write_file"):
        raise ResourceRejected("No controlled executor for this action")
    allowed = {"path", "target"} | ({"content"} if action.type == "write_file" else set())
    if set(action.payload) - allowed:
        raise ResourceRejected("Unsupported controlled file arguments")
    for alias in ("path", "target"):
        if alias in action.payload and action.payload[alias] != action.target:
            raise ResourceRejected("File target alias mismatch")
    if action.type == "write_file":
        value = action.payload.get("content")
        if not isinstance(value, str):
            raise ResourceRejected("write_file requires UTF-8 text content")
        try:
            if len(value.encode("utf-8")) > MAX_BYTES:
                raise ResourceRejected("File content exceeds executor limit")
        except UnicodeError as exc:
            raise ResourceRejected("Invalid UTF-8 text") from exc


class _Info(ctypes.Structure):
    _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME),
                ("access", w.FILETIME), ("write", w.FILETIME),
                ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD),
                ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]


class BoundFile:
    def __init__(self, action, protected=()):
        validate_action(action)
        if os.name != "nt":
            raise ResourceRejected("Controlled file execution currently requires Windows NTFS")
        self.action = action.model_copy(deep=True)
        self.handles = []
        self.file = None
        self.content = None
        path = PureWindowsPath(action.target)
        # Reject devices, UNC, ADS, traversal and Win32 ambiguous path spellings.
        raw_parts = re.split(r"[\\/]", action.target)
        if (not re.fullmatch(r"[A-Za-z]:", path.drive) or not path.is_absolute()
                or len(path.parts) < 2 or len(action.target) > 240
                or any(p in (".", "..") for p in raw_parts)
                or any(p.endswith((".", " ")) or any(c in p for c in '<>:"|?*\x00')
                       or any(ord(c) < 32 for c in p)
                       or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?", p)
                       for p in path.parts[1:])):
            raise ResourceRejected("Only unambiguous absolute local file paths are supported")
        self.path = str(path)
        for root in protected:
            protected_path = Path(root).resolve()
            # Do not resolve a caller path before checking the drive and locking
            # its ancestors: resolution itself could follow a network junction.
            actual = Path(self.path)
            if actual == protected_path or actual.is_relative_to(protected_path):
                raise ResourceRejected("Executor cannot access its control-plane files")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "GetFileInformationByHandle": ([w.HANDLE, ctypes.POINTER(_Info)], w.BOOL),
            "GetFinalPathNameByHandleW": ([w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD], w.DWORD),
            "GetDriveTypeW": ([w.LPCWSTR], w.UINT),
            "GetVolumeInformationW": ([w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD),
                                        ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD], w.BOOL),
            "ReadFile": ([w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID], w.BOOL),
            "WriteFile": ([w.HANDLE, w.LPCVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID], w.BOOL),
            "SetFilePointerEx": ([w.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), w.DWORD], w.BOOL),
            "SetEndOfFile": ([w.HANDLE], w.BOOL),
            "FlushFileBuffers": ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = args, result
        try:
            if self.k.GetDriveTypeW(path.anchor) != 3:
                raise ResourceRejected("Executor requires a fixed local NTFS volume")
            fs = ctypes.create_unicode_buffer(32)
            self._ok(self.k.GetVolumeInformationW(path.anchor, None, 0, None, None, None, fs, len(fs)))
            if fs.value != "NTFS":
                raise ResourceRejected("Executor requires a fixed local NTFS volume")
            parents = []
            for parent in reversed(path.parents):
                handle = self._open(str(parent), directory=True)
                info = self._info(handle)
                if not info.attributes & 0x10:
                    raise ResourceRejected("Ancestor is not a directory")
                parents.append(self._identity(info))
            try:
                self.file = self._open(self.path, writable=action.type == "write_file")
            except OSError as exc:
                if exc.winerror != 2 or action.type != "write_file":
                    raise
            file_state = None
            if self.file is not None:
                info = self._regular(self.file)
                size = (info.size_high << 32) | info.size_low
                if size > MAX_BYTES:
                    raise ResourceRejected("Existing file exceeds executor limit")
                data = self._read(size)
                # Reading must be deterministic text; writes may replace binary data.
                if action.type == "read_file":
                    self.content = data.decode("utf-8")
                file_state = {**self._identity(info), "size": size,
                              "sha256": hashlib.sha256(data).hexdigest(),
                              "write_time": (info.write.dwHighDateTime << 32) | info.write.dwLowDateTime}
            self.binding = {"backend": "windows-ntfs-v1", "path": self.path,
                            "parents": parents, "file": file_state}
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _ok(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    @staticmethod
    def _identity(info):
        return {"volume": info.volume, "id": (info.index_high << 32) | info.index_low,
                "created": (info.creation.dwHighDateTime << 32) | info.creation.dwLowDateTime}

    def _info(self, handle):
        info = _Info()
        self._ok(self.k.GetFileInformationByHandle(handle, ctypes.byref(info)))
        if info.attributes & 0x400:
            raise ResourceRejected("Reparse points are prohibited")
        return info

    def _regular(self, handle):
        info = self._info(handle)
        if info.attributes & 0x10 or info.links != 1:
            raise ResourceRejected("Only regular files with one hard link are supported")
        return info

    def _open(self, path, directory=False, writable=False, create=False):
        access = 0x80 if directory else 0x80000000 | (0x40000000 if writable else 0)
        handle = self.k.CreateFileW(path, access, 1 if directory else 0, None, 1 if create else 3,
                                   0x00200000 | (0x02000000 if directory else 0), None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.handles.append(handle)
        self._info(handle)
        final = ctypes.create_unicode_buffer(32768)
        length = self._ok(self.k.GetFinalPathNameByHandleW(handle, final, len(final), 0))
        if length >= len(final) or final.value.removeprefix("\\\\?\\").casefold().rstrip("\\") != path.casefold().rstrip("\\"):
            raise ResourceRejected("Resolved handle path differs from requested path")
        return handle

    def _read(self, size):
        buffer = ctypes.create_string_buffer(size + 1)
        count = w.DWORD()
        self._ok(self.k.ReadFile(self.file, buffer, size + 1, ctypes.byref(count), None))
        if count.value != size:
            raise ResourceRejected("File changed during snapshot")
        return buffer.raw[:count.value]

    def run(self):
        if self.file is not None:
            self._regular(self.file)
        if self.action.type == "read_file":
            return {"content": self.content, "encoding": "utf-8"}
        data = self.action.payload["content"].encode("utf-8")
        if self.file is None:
            # CREATE_NEW never overwrites a file inserted after the missing snapshot.
            self.file = self._open(self.path, writable=True, create=True)
        self._regular(self.file)
        self._ok(self.k.SetFilePointerEx(self.file, 0, None, 0))
        buffer = ctypes.create_string_buffer(data)
        count = w.DWORD()
        self._ok(self.k.WriteFile(self.file, buffer, len(data), ctypes.byref(count), None))
        if count.value != len(data):
            raise OSError("Incomplete controlled write")
        self._ok(self.k.SetEndOfFile(self.file))
        self._ok(self.k.FlushFileBuffers(self.file))
        self._regular(self.file)
        return {"bytes_written": count.value}

    def close(self):
        for handle in reversed(self.handles):
            self.k.CloseHandle(handle)
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
