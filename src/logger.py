import json
from termcolor import cprint
from datetime import datetime
from configparser import SectionProxy


log_colors = {
    'control': ('yellow', None),
    'debug': ('green', None),
    'info': ('white', None),
    'warning': ('grey', 'on_yellow'),
    'exception': ('grey', 'on_red'),
    'upstream': ('magenta', None),
    'explanation': ('grey', 'on_cyan'),
    #'explanation': ('cyan', None),
    'detection': ('grey', 'on_magenta'),
    #'detection': ('red', None),
    'input': ('grey', 'on_white'),
    #'input': ('white', None),
    'output': ('cyan', None),
    'unexpected': ('grey', 'on_magenta'),
    # '': '',
}

colored = False
log_indent = None
console = False
logging_file = ''


def logger_init(config: SectionProxy):
    global colored
    global console
    global log_indent
    global logging_file

    colored = config.getboolean('logger', 'colored')
    console = config.getboolean('logger', 'console')
    log_indent = config['logger']['indent']
    logging_file = config['logger']['file']

    if log_indent:
        log_indent = int(log_indent)
    else:
        log_indent = None


def log(dataset: str, session=None, event_raw=None, **kwargs):

    global colored
    global console
    global log_indent
    global logging_file

    log_dict = {
        '@timestamp': datetime.utcnow(),
        'event.dataset': dataset,
    }

    # Show 'message' in the beggining of the line
    if 'message' in kwargs:
        log_dict['message'] = kwargs.pop('message')

    if session is not None:
        transport = session.client_reader._transport
        log_dict['source.ip'] = transport.get_extra_info('peername')[0]
        log_dict['source.port'] = transport.get_extra_info('peername')[1]
        log_dict['destination.ip'] = transport.get_extra_info('sockname')[0]
        log_dict['destination.port'] = transport.get_extra_info('sockname')[1]

        log_dict['session.id'] = session.id

    if event_raw is not None:
        log_dict['event.raw'] = event_raw

    log_dict.update(kwargs)

    if console:
        if colored:
            line_colors = log_colors.get(dataset, ('red', 'on_green'))
            cprint(json.dumps(log_dict, default=str, indent=log_indent), line_colors[0], line_colors[1])
        else:
            print(json.dumps(log_dict, default=str, indent=log_indent), flush=True)
    if logging_file:
        raise NotImplementedError
