from enum import Enum


class VariableType(Enum):
    BOOL          = 0x00000000  # noqa: E221
    SHORT_LENGTH  = 0x01000000  # noqa: E221
    DWORD         = 0x08000000  # noqa: E221
    QWORD         = 0x10000000  # noqa: E221
    IP6           = 0x18000000  # noqa: E221
    STRING        = 0x20000000  # noqa: E221
    MESSAGE       = 0x28000000  # noqa: E221
    RAW           = 0x30000000  # noqa: E221
    BOOL_ARRAY    = 0x80000000  # noqa: E221
    DWORD_ARRAY   = 0x88000000  # noqa: E221
    QWORD_ARRAY   = 0x90000000  # noqa: E221
    IP6_ARRAY     = 0x98000000  # noqa: E221
    STRING_ARRAY  = 0xa0000000  # noqa: E221
    MESSAGE_ARRAY = 0xa8000000  # noqa: E221
    RAW_ARRAY     = 0xb0000000  # noqa: E221
