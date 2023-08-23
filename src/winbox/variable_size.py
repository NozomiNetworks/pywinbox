from enum import Enum


class VariableSize(Enum):
    BOOL   = 1   # noqa: E221
    BYTE   = 1   # noqa: E221
    SHORT  = 2   # noqa: E221
    DWORD  = 4   # noqa: E221
    QWORD  = 8   # noqa: E221
    IP6    = 16  # noqa: E221
