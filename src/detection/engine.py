import importlib
from glob import glob
from logger import log
from winbox.message import Frame


class Engine:

    rules = {}

    def __init__(self):
        self.load_rules()

    def load_rules(self):
        for rule_path in glob('detection/rules/*.py'):
            rule_name = rule_path.rsplit('/', 1)[-1][:-3]
            if rule_name in ['__init__', 'rule']:
                continue
            log('debug', message=f'Loading rule {rule_name}')
            module = importlib.import_module(f'detection.rules.{rule_name}')
            self.rules[rule_name] = getattr(module, rule_name.capitalize())()

    def scan(self, frame: Frame) -> list:
        detections = []

        try:
            for scanner in self.rules.values():
                if scanner.scan(frame):
                    detections.append(scanner)
        except Exception as why:
            print(f'[!] @scan_request Unexpected exception: {why}')

        return detections
