__version__ = "4.2.0"


import logging
logging.getLogger("declib").addHandler(logging.NullHandler())
from declib.logger import Loggers
loggers = Loggers()
del Loggers
del logging
