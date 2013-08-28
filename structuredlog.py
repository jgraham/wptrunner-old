from collections import deque
from threading import current_thread, RLock
import time

import mozlog

loggers = {}

def getLogger(name, handler=None):
    if name not in loggers:
        loggers[name] = mozlog.getLogger(name, handler)
    return StructuredLogger(loggers[name])

class StructuredLogger(object):
    _lock = RLock()

    def __init__(self, logger):
        self._logger = logger 
        self._log_queue = deque([])
        self.buffer_default = False

    def __getattr__(self, name):
        return getattr(self._logger, name)

    def log(self, level, params):
        with self._lock:
            self._logger.log_structured(level, params)

    def log_defer(self, level, params):
        self._log_queue.append((level, params))

    def flush(self):
        with self._lock:
            while self._log_queue:
                self._logger.log_structured(*self._log_queue.popleft())

def _test_log_func(level_name):
    def log(self, params, buffer=None):
        if not hasattr(params, "iteritems"):
            params = {"msg":params}

        all_params = {"_thread":current_thread().name,
                      "time":time.time()}
        all_params.update(params)
        buffer = buffer if buffer is not None else self.buffer_default
        if buffer:
            self.log_defer(level_name, all_params)
        else:
            self.log(level_name, all_params)
    return log

for name in ["critical", "error", "warning", "info", "debug",
             "test-start", "test-end", "test-pass", "test-fail",
             "test-known-fail", "process-crash"]:
    parts = name.split("-")
    action = "-".join(item.upper() for item in parts)
    for i, part in enumerate(parts[1:]):
        parts[i+1] = part.title()
    func_name = "".join(parts)
    setattr(StructuredLogger, func_name, _test_log_func(action))
