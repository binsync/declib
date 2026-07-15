__version__ = "4.0.2"


import logging
logging.getLogger("declib").addHandler(logging.NullHandler())
from declib.logger import Loggers
loggers = Loggers()
del Loggers
del logging
