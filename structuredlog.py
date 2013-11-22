import sys
from collections import deque, defaultdict
from threading import current_thread, RLock
import time
import socket
import json
import weakref

#An alternate proposal for logging:
#Allowed actions, and subfields:
#  suite_start
#      tests
#  suite_end
#  test_start
#      test
#  test_end
#      test
#      status [OK | ERROR | TIMEOUT | CRASH | ASSERT?]
#      unexpected [True | not given]
#  test_result
#      test
#      subtest
#      status [PASS | FAIL | TIMEOUT | NOTRUN]
#      unexpected [True | not given]
#  process_output
#      process
#      command
#      data
#  log
#      level
#      message

_loggers = defaultdict(dict)

#Semantics are a bit weird
#Because the buffers are per-thread you need a different TestOutput instance on each thread
#However there is exactly one instance per thread and the handlers are shared cross-thread
#Multiple processes are not supported
#This should be made more sane

def getOutputLogger(name):
    thread_name = current_thread().name
    if not name in _loggers or thread_name not in _loggers[name] or _loggers[name][thread_name] is None:
        output_logger = TestOutput(name)
        _loggers[name][thread_name] = weakref.ref(output_logger)
    rv = _loggers[name][thread_name]()
    return rv

class LoggedRLock(object):
    def __init__(self, name):
        self.name = name
        self._lock = RLock()

    def __enter__(self):
        sys.stderr.write("Lock %s requested by %s\n" % (self.name, current_thread().name))
        self._lock.acquire()
        sys.stderr.write("Lock %s acquired by %s\n" % (self.name, current_thread().name))
        sys.stderr.flush()

    def __exit__(self, *args):
        sys.stderr.write("Lock %s being released by %s\n" % (self.name, current_thread().name))
        sys.stderr.flush()
        self._lock.release()

class TestOutput(object):
    _lock = RLock()
    _log_levels = dict((k.upper(),v) for v,k in
                       enumerate(["critical", "error", "warning", "info", "debug"]))
    _handlers = defaultdict(list)

    def __init__(self, name, handlers=None):
        self.name = name
        self._log_queue = deque([])

        self._level = self._log_levels["DEBUG"]

    def add_handler(self, handler):
        self._handlers[self.name].append(handler)

    @property
    def handlers(self):
        return self._handlers[self.name]

    def _log_data(self, action, data=None):
        if data is None:
            data = {}
        with self._lock:
            log_data = self._make_log_data(action, data)
            for handler in self.handlers:
                handler(log_data)

    def _make_log_data(self, action, data):
        all_data = {"action":action,
                    "time":int(time.time() * 1000),
                    "thread":current_thread().name,
                    "source":"%s (%d)" % (self.name, id(self))}
        all_data.update(data)
        return all_data

    def _queue_data(self, action, data=None):
        with self._lock:
            if data is None:
                data = {}
            self._log_queue.append(self._make_log_data(action, data))

    def suite_start(self, tests):
        self._log_data("suite_start", {"tests":tests})

    def suite_end(self):
        self._log_data("suite_end")

    def test_start(self, test):
        self._queue_data("test_start", {"test":test})

    def test_status(self, test, subtest, status, message=None, unexpected=False):
        if status.upper() not in ["PASS", "FAIL", "TIMEOUT", "NOTRUN", "ASSERT"]:
            raise ValueError, "Unrecognised status %s" % statsu
        data = {"test":test,
                "subtest":subtest,
                "status": status.upper()}
        if message is not None:
            data["message"] = message
        if unexpected:
            data["unexpected"] = True
        self._queue_data("test_status", data)

    def test_end(self, test, status, message=None, unexpected=False):
        if status.upper() not in ["OK", "ERROR", "TIMEOUT", "CRASH", "ASSERT"]:
            raise ValueError, "Unrecognised status %s" % statsu
        data = {"test":test,
                "status": status.upper()}
        if message is not None:
            data["message"] = message
        if unexpected:
            data["unexpected"] = True
        self._queue_data("test_end", data)
        self.flush()

    def process_output(self, process, data, command=None):
        data = {"process":process, "data": data}
        if command is not None:
            data["command"] = command
        self._queue_data("process_output", data)

    def flush(self):
        with self._lock:
            while self._log_queue:
                entry = self._log_queue.popleft()
                for handler in self.handlers:
                    handler(entry)

def _log_func(level_name):
    def log(self, message, params=None):
        level = self._log_levels[level_name]
        if level <= self._level:
            if params is None:
                params = {}
            data = {"level": level_name, "message": message}
            data.update(params)
            self._log_data("log", data)
    return log

for level_name in TestOutput._log_levels:
    setattr(TestOutput, level_name.lower(), _log_func(level_name))

JSONFormatter = lambda:json.dumps

class StreamHandler(object):
    _lock = RLock()
    def __init__(self,  stream=sys.stderr, formatter=JSONFormatter()):
        self.stream = stream
        self.formatter = formatter

    def __call__(self, data):
        formatted = self.formatter(data)
        with self._lock:
            self.stream.write(formatted + "\n")
            self.stream.flush()

#There is lots more fanciness in the logging equivalent of this
class SocketHandler(object):
    def __init__(self, host, port, formatter=JSONFormatter()):
        self.host = host
        self.port = port
        self.socket = None

    def __call__(self, data):
        if not self.socket:
            self.socket = self.create_socket()

        self.socket.write(self.formatter(data) + "\n")
        self.socket.flush()

    def create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        return sock

    def close(self):
        if self.socket:
            self.socket.close()


def get_adapter_cls():
    #Hide this in a function so that we don't import logging unless
    #it is really needed
    import logging

    class LoggingAdapter(logging.Handler):
        def __init__(self, name=None, level=logging.NOTSET):
            self.structured = TestOutput(name)
            logging.Handler.__init__(self, level=level)

        def emit(self, record):
            if record.levelname in self.structured._log_levels:
                log_func = getattr(self.structured, record.levelname.lower())
            else:
                log_func = self.logger.debug
            log_func(record.msg)

        def handle(self, record):
            self.emit(record)

    return LoggingAdapter


def action_filter(log_iter, actions):
    for item in log_iter:
        if item["action"] in actions:
            yield item

def map_action(log_iter, action_map):
    for item in log_iter:
        if item["action"] in action_map:
            yield action_map[item["action"]](item)

def read_logs(log_f):
    for line in log_f:
        try:
            yield json.loads(line)
        except ValueError:
            print line
