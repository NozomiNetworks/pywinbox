from winbox.message import Frame
from winbox.message import Message


class Rule:

    title = "Title placeholder"
    description = "Description placeholder"

    def scan(request: Frame) -> bool:
        raise NotImplementedError
