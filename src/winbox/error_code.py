from enum import Enum


class ErrorCode(Enum):
    NOT_IMPLEMENTED   = 0x00fe0002  # noqa: E221
    NOT_IMPLEMENTEDV2 = 0x00fe0003  # noqa: E221
    OBJ_NONEXISTANT   = 0x00fe0004  # noqa: E221
    NOT_PERMITTED     = 0x00fe0009  # noqa: E221
    TIMEOUT           = 0x00fe000d  # noqa: E221
    OBJ_NONEXISTANT2  = 0x00fe0011  # noqa: E221
    BUSY              = 0x00fe0012  # noqa: E221
