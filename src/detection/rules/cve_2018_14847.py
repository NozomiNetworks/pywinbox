from winbox.message import Frame
from detection.rules.rule import Rule
from winbox.variable_name import VariableName


class Cve_2018_14847(Rule):

    description = "Unauthenticated users password dump"
    title = "CVE-2018-14847"

    def scan(self, request: Frame):

        # open file for reading
        open_file = {
            VariableName.SYS_TO: [2, 2],
            VariableName.SYS_CMD: 7,
        }

        if not request.message.has_with_value(open_file):
            return False

        str_1 = request.message.get_variable('string.1')
        if str_1 is not None and 'user.dat' in str_1.value:
            return True

        return False
