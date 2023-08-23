from winbox.message import Frame
from detection.rules.rule import Rule
from winbox.variable_name import VariableName


class Cve_2019_3943(Rule):

    description = "Authenticated path traversal"
    title = "CVE-2019-3943"

    def scan(self, request: Frame):

        # open file for reading
        open_file = {
            VariableName.SYS_TO: [72, 1],
            VariableName.SYS_CMD: 3,
        }

        if not request.message.has_with_value(open_file):
            return False

        str_1 = request.message.get_variable('string.1')
        if str_1 is not None and '../' in str_1.value:
            return True

        return False
