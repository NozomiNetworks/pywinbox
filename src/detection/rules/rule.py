from winbox.message import Frame


class Rule:

    title = "Title placeholder"
    description = "Description placeholder"

    def scan(request: Frame) -> bool:
        raise NotImplementedError
