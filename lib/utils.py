import logging
import sys
import socket

def idle_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != '\n':
            self.logger.log(self.level, message)
            
def init_logging():
    if len(sys.argv)>1 and sys.argv[1] == "--debug":
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        ch = logging.FileHandler("firefly.log")
        ch.setFormatter(logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] - %(message)s'))
        logger.addHandler(ch)
        sys.stdout = LoggerWriter(logger, logging.DEBUG)
        sys.stderr = LoggerWriter(logger, logging.DEBUG)
    