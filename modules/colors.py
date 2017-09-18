

def get_color(color):

    if color == 'HEADER':
        return '\033[95m'
    if color == 'OKBLUE':
        return '\033[94m'
    if color == 'OKGREEN':
        return '\033[92m'
    if color == 'WHITE':
        return '\033[37m'
    if color == 'WARNING': 
        return '\033[93m'
    if color == 'FAIL': 
        return '\033[91m'
    if color == 'ORANGE': 
        return '\033[33m'
    if color == 'ENDC':
        return '\033[0m'
    if color == 'BOLD': 
        return '\033[1m'
    if color == 'GRAY':
        return '\033[90m'
    if color == 'UNDERLINE':
        return '\033[4m'
    if color == 'FAIL':
        return '\033[91m'
    if color == 'FAIL2':
        return '\033[41m'
    else:
        return