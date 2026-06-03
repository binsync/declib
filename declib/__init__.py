__version__ = "3.8.0"


import logging
logging.getLogger("declib").addHandler(logging.NullHandler())
from declib.logger import Loggers
loggers = Loggers()
del Loggers
del logging
