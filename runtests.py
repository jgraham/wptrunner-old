import sys
import os
import argparse
import urllib
import urlparse
import time
import json
from Queue import Queue, Empty
import multiprocessing
from multiprocessing import Process, Pipe
import threading
import urllib2
import socket
import signal
import hashlib
from collections import defaultdict, deque
import pstats
import cProfile
import uuid

import marionette
import mozprocess
from mozprofile.profile import Profile
from mozrunner import FirefoxRunner
import mozinfo

import structuredlog
import expected

DEFAULT_TIMEOUT = 20 #seconds

#TODO
# reftest details (window size+ lots more)
# logging
# Documentation
# better status report
# correct output format
# webdriver tests
# HTTP server crashes
# Expected test results

logger = structuredlog.getOutputLogger("WPT")



def make_wrapper(cmd, cmd_args):
    class WrappedCommand(type):
        def __call__(cls, *args, **kwargs):
            all_args = ([cmd] + cmd_args + args[0],) + args[1:]
            return super(WrappedCommand, cls).__call__(*all_args, **kwargs)

    def inner(cls):
        class Command(cls):
            __metaclass__ = WrappedCommand
        return Command

    return inner

XvfbWrapped = make_wrapper("xvfb-run", ["-a", "--server-args=+extension RANDR -screen 0 800x600x24"])


class HttpServer(mozprocess.ProcessHandlerMixin):
    def __init__(self, path, test_root, host="127.0.0.1", port=8000,
                 **kwargs):
        """HTTP Server process.

        :param path: Path to the server binary
        :param test_root: Path to the root of the tests
        :param host: Hostname to run the server on
        :param port: Port to run the server on"""
        self.path = path
        self.test_root = test_root
        self.host = host
        self.port = port

        mozprocess.ProcessHandlerMixin.__init__(self, path, self.get_args(),
                                                **kwargs)

    def get_args(self):
        return [self.test_root,
                "--port=%i" % self.port,
                "--host=%s" % self.host]

    @property
    def url(self):
        return "http://%s:%i/" % (self.host, self.port)

class HttpServerManager(object):
    #Could perhaps just fold this in to the HttpServer class
    def __init__(self, binary_path, test_path, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.proc = HttpServer(binary_path, test_path, host, port,
                               stderr=sys.stderr)
        self.timeout = 10

    def start(self):
        self.proc.run()

    def ping(self):
        #Might be easier just to see if it is possible to connect with a socket
        try:
            urllib2.urlopen("http://%s:%i" % (self.host, self.port), timeout=self.timeout)
        except socket.timeout:
            return False
        except urllib2.HTTPError:
            return True
        except urllib2.URLError:
            return False
        return True

    def stop(self):
        self.proc.kill()

    def restart(self):
        self.stop()
        self.start()


def start_http_server(http_server_path, test_path):
    server_manager = HttpServerManager(http_server_path, test_path)
    server_manager.start()
    server_started = False
    for i in xrange(10):
        server_started = server_manager.ping()
        if server_started:
            break
        time.sleep(1)

    if not server_started:
        sys.stderr.write("Failed to start HTTP server")
        server_manager.stop()
        sys.exit(1)
    return server_manager


def get_free_port(start_port, exclude=None):
    port = start_port
    while True:
        if exclude and port in exclude:
            port += 1
            continue
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        except socket.error:
            port += 1
        else:
            return port
        finally:
            s.close()

class RunInfo(object):
    def __init__(self, debug):
        self.platform = mozinfo.info
        self.debug = debug


class Test(object):
    def __init__(self, url, expectations, timeout=None):
        self.url = url
        self.expectations = expectations
        self.timeout = timeout

    @property
    def id(self):
        return self.url

    def disabled(self, run_info):
        if "FILE" in self.expectations:
            return "disabled" in self.expectations["FILE"]

    def expected_file(self, run_info):
        return self.expected_subtest(run_info, "FILE")

    def expected_subtest(self, run_info, name):
        if name in self.expectations:
            return self.expectations[name].get("expected", "PASS").upper()
        else:
            return "PASS"

    def disabled_subtest(self, run_info, name):
        if name in self.expectations:
            return "disabled" in self.expectations[name]

    @classmethod
    def from_json(cls, obj):
        raise NotImplementedError

class TestharnessTest(Test):
    @property
    def id(self):
        return self.url

class ReftestTest(Test):
    def __init__(self, url, ref_url, ref_type, expectations, timeout=None):
        self.url = url
        self.ref_url = ref_url
        if ref_type not in ("==", "!="):
            raise ValueError
        self.ref_type = ref_type
        self.expectations = expectations
        self.timeout = timeout

    @property
    def id(self):
        return self.url, self.ref_type, self.ref_url

def construct_test(manifest_test, expectations):
    test_cls = {"reftest":ReftestTest,
                "testharness":TestharnessTest}[manifest_test.item_type]
    if test_cls == ReftestTest:
        return test_cls(manifest_test.url,
                        manifest_test.ref_url,
                        manifest_test.ref_type,
                        expectations,
                        timeout=manifest_test.timeout)
    else:
        return test_cls(manifest_test.url,
                        expectations,
                        timeout=manifest_test.timeout)

class HarnessResult(object):
    statuses = set(["OK", "ERROR", "TIMEOUT", "CRASH"])

    def __init__(self, status, message):
        if status not in self.statuses:
            raise ValueError("Unrecognised status %s" % status)
        self.status = status
        self.message = message


class TestResult(object):
    statuses = set(["PASS", "FAIL", "TIMEOUT", "NOTRUN"])

    def __init__(self, name, status, message):
        self.name = name
        if status not in self.statuses:
            raise ValueError("Unrecognised status %s" % status)
        self.status = status
        self.message = message

Stop = object()

class TestRunner(object):
    def __init__(self, http_server_url, command_pipe, marionette_port=None):
        self.http_server_url = http_server_url
        self.command_pipe = command_pipe
        if marionette_port is None:
            marionette_port = get_free_port(2828)
        self.marionette_port = marionette_port
        self.timer = None
        self.window_id = str(uuid.uuid4())

    def setup(self):
        logger.debug("Connecting to marionette on port %i" % self.marionette_port)
        #Supporting multiple processes requires a choice of ports here
        self.browser = marionette.Marionette(host='localhost', port=self.marionette_port)
        #XXX Move this timeout somewhere
        success = self.browser.wait_for_port(20)
        if success:
            logger.debug("Marionette port aquired")
            self.browser.start_session()
            logger.debug("Marionette session started")
            self.send_message("setup_succeeded")
        else:
            logger.error("Failed to connect to marionette")
            self.send_message("setup_failed")
        return success

    def teardown(self):
        self.command_pipe.close()
        #Close the marionette session

    def run(self):
        logger.debug("Run TestRunner")
        self.setup()
        commands = {"run_test": self.run_test,
                    "stop": self.stop}
        try:
            while True:
                command, args = self.command_pipe.recv()
                if commands[command](*args) is Stop:
                    break
        finally:
            self.teardown()

    def run_test(self, test):
        assert len(self.browser.window_handles) == 1

        #Lock to prevent races between timeouts and other results
        #This might not be strictly necessary if we need to deal
        #with the result changing post-hoc anyway (e.g. due to detecting
        #a crash after we get the data back from marionette)
        result = None
        result_flag = threading.Event()
        result_lock = threading.Lock()

        def timeout_func():
            with result_lock:
                if not result_flag.is_set():
                    result_flag.set()
                    result = (HarnessResult("TIMEOUT", None), [])
                    self.send_message("test_ended", test, result)

        timeout = test.timeout if test.timeout else DEFAULT_TIMEOUT

        self.timer = threading.Timer(timeout + 10, timeout_func)
        self.timer.start()

        self.browser.set_script_timeout(timeout * 1000)

        try:
            result = self.convert_result(test, self.do_test(test))
        except marionette.errors.ScriptTimeoutException:
            with result_lock:
                if not result_flag.is_set():
                    result_flag.set()
                    result = (HarnessResult("TIMEOUT", None), [])
            #Clean up any unclosed windows
            #This doesn't account for the possibility the browser window
            #is totally hung. That seems less likely since we are still
            #getting data from marionette, but it might be just as well
            #to do a full restart in this case
            #XXX - this doesn't work at the moment because window_handles
            #only returns OS-level windows (see bug 907197)
            # while True:
            #     handles = self.browser.window_handles
            #     self.browser.switch_to_window(handles[-1])
            #     if len(handles) > 1:
            #         self.browser.close()
            #     else:
            #         break
            #Now need to check if the browser is still responsive and restart it if not
        except (socket.timeout, marionette.errors.InvalidResponseException):
            #This can happen on a crash
            #XXX Maybe better to have a specific crash message?
            #Also, should check after the test if the firefox process is still running
            #and otherwise ignore any other result and set it to crash
            with result_lock:
                if not result_flag.is_set():
                    result_flag.set()
                    result = (HarnessResult("CRASH", None), [])
        finally:
            self.timer.cancel()

        with result_lock:
            if result:
                self.send_message("test_ended", test, result)

    def do_test(self, test):
        raise NotImplementedError

    def convert_result(self, test, result):
        raise NotImplementedError

    def stop(self):
        return Stop

    def send_message(self, command, *args):
        self.command_pipe.send((command, args))


class TestharnessTestRunner(TestRunner):
    harness_codes = {0: "OK",
                     1: "ERROR",
                     2: "TIMEOUT"}

    test_codes = {0: "PASS",
                  1: "FAIL",
                  2: "TIMEOUT",
                  3: "NOTRUN"}

    def __init__(self, *args, **kwargs):
        TestRunner.__init__(self, *args, **kwargs)
        self.script = open("testharness.js").read()

    def setup(self):
        if TestRunner.setup(self):
            self.browser.navigate("data:text/html," + urllib.quote(open("testharness.html").read() % {"window_id": self.window_id, "title": threading.current_thread().name}))

    def do_test(self, test):
        return self.browser.execute_async_script(
            self.script % {"abs_url": urlparse.urljoin(self.http_server_url, test.url),
                           "url": test.url,
                           "window_id": self.window_id}, new_sandbox=False)

    def convert_result(self, test, result):
        """Convert a JSON result into a (HarnessResult, [TestResult]) tuple"""
        assert result["test"] == test.url, "Got results from %s, expected %s" % (result["test"], test.url)
        return (HarnessResult(self.harness_codes[result["status"]], result["message"]),
                [TestResult(test["name"], self.test_codes[test["status"]],
                            test["message"]) for test in result["tests"]])


class ReftestTestRunner(TestRunner):
    def __init__(self, *args, **kwargs):
        TestRunner.__init__(self, *args, **kwargs)
        with open("reftest.js") as f:
            self.script = f.read()
        self.ref_hashes = {}
        self.ref_urls_by_hash = defaultdict(set)

    def do_test(self, test):
        url, ref_type, ref_url = test.url, test.ref_type, test.ref_url
        hashes = {"test": None,
                  "ref": self.ref_hashes.get(ref_url)}
        for url_type, url in [("test", url), ("ref", ref_url)]:
            if hashes[url_type] is None:
                #Would like to do this in a new tab each time, but that isn't
                #easy with the current state of marionette
                self.browser.navigate(urlparse.urljoin(self.http_server_url, url))
                screenshot = self.browser.screenshot()
                #strip off the data:img/png, part of the url
                assert screenshot.startswith("data:image/png;base64,")
                screenshot = screenshot.split(",", 1)[1]
                hashes[url_type] = hashlib.sha1(screenshot).hexdigest()

        self.ref_urls_by_hash[hashes["ref"]].add(ref_url)

        self.ref_hashes[ref_url] = hashes["ref"]
        if ref_type == "==":
            passed = hashes["test"] == hashes["ref"]
        elif ref_type == "!=":
            passed = hashes["test"] != hashes["ref"]
        else:
            raise ValueError

        return "PASS" if passed else "FAIL"

    def teardown(self):
        count = 0
        for hash_val, urls in self.ref_urls_by_hash.iteritems():
            if len(urls) > 1:
                print "The following %i reference urls appear to be equivalent:\n " % len(urls), "\n  ".join(urls)
                count += len(urls) - 1
        print "In total %i screnshots could be avoided" % count
        TestRunner.teardown(self)

    def convert_result(self, test, result):
        """Convert a JSON result into a (HarnessResult, [TestResult]) tuple"""
        return (HarnessResult("OK", None),
                [TestResult("test", result, None)])


def start_runner(runner_cls, http_server_url, marionette_port, command_pipe):
    runner = runner_cls(http_server_url, command_pipe, marionette_port=marionette_port)
    runner.run()


class FirefoxProcess(mozprocess.ProcessHandlerMixin):
    pass


class TestRunnerManager(threading.Thread):
    """Thread that owns a single TestRunner process and any processes required
    by the TestRunner (e.g. the Firefox binary)"""

    init_lock = threading.Lock()

    def __init__(self, server_url, firefox_binary, run_info, tests_queue,
                 stop_flag, runner_cls=TestharnessTestRunner,
                 marionette_port=None, process_cls=FirefoxProcess):
        self.http_server_url = server_url
        self.firefox_binary = firefox_binary
        self.tests_queue = tests_queue
        self.run_info = run_info
        self.stop_flag = stop_flag
        self.command_pipe = None
        self.firefox_runner = None
        self.test_runner_proc = None
        self.runner_cls = runner_cls
        self.marionette_port = marionette_port
        self.process_cls = process_cls
        threading.Thread.__init__(self)
        #This is started in the actual new thread
        self.logger = None
        #This may not really be what we want
        self.daemon = True
        self.setup_fail_count = 0
        self.max_setup_fails = 5
        self.init_timer = None

    def run(self):
        self.logger = structuredlog.getOutputLogger("WPT")
        self.init()
        while True:
            commands = {"test_ended":self.test_ended,
                        "setup_succeeded": self.setup_succeeded,
                        "setup_failed": self.setup_failed}
            has_data = self.command_pipe.poll(1)
            if has_data:
                command, data = self.command_pipe.recv()
                if commands[command](*data) is Stop:
                    break
            else:
                if self.stop_flag.is_set():
                    self.stop_runner(graceful=True)
                    break
                elif not self.test_runner_proc.is_alive():
                    #This happens when we run out of tests;
                    #We ask the runner to stop, it shuts itself
                    #down and then we end up here
                    #An alternate implementation strategy would be to have the
                    #runner signal that it is done just before it terminates
                    self.firefox_runner.stop()
                    break

    def init(self):
        #It seems that this lock is helpful to prevent some race that otherwise
        #sometimes stops the spawned processes initalising correctly, and
        #leaves this thread hung
        with self.init_lock:
            def init_failed():
                self.logger.error("Init failed")
                self.setup_failed()

            #TODO: make this timeout configurable
            self.init_timer = threading.Timer(30, self.setup_failed)
            self.init_timer.start()

            self.command_pipe, remote_end = Pipe()

            self.start_firefox()
            self.start_test_runner(remote_end)

    def start_firefox(self):
        env = os.environ.copy()
        env['MOZ_CRASHREPORTER_NO_REPORT'] = '1'

        profile = Profile()
        profile.set_preferences({"marionette.defaultPrefs.enabled": True,
                                 "marionette.defaultPrefs.port": self.marionette_port,
                                 "dom.disable_open_during_load": False,
                                 "dom.max_script_run_time": 0})

        self.firefox_runner = FirefoxRunner(profile,
                                            self.firefox_binary,
                                            cmdargs=["--marionette"],
                                            env=env,
                                            kp_kwargs = {"processOutputLine":[self.on_output]},
                                            process_class=self.process_cls)
        self.logger.debug("Starting Firefox")
        self.firefox_runner.start()
        self.logger.debug("Firefox Started")

    def start_test_runner(self, remote_connection):
        self.test_runner_proc = Process(target=start_runner,
                                        args=(self.runner_cls,
                                              self.http_server_url,
                                              self.marionette_port,
                                              remote_connection))
        self.logger.debug("Starting test runner")
        self.test_runner_proc.start()
        self.logger.debug("Test runner started")

    def send_message(self, command, *args):
        self.command_pipe.send((command, args))

    def stop_runner(self, graceful=True):
        self.logger.debug("Stopping runner")
        if graceful:
            self.test_runner_proc.join(10)
            if self.test_runner_proc.is_alive():
                graceful = False
        self.firefox_runner.stop()
        if not graceful:
            self.test_runner_proc.terminate()
        self.logger.flush()
        self.command_pipe.close()

    def start_next_test(self):
        try:
            test = self.tests_queue.get(False)
        except Empty:
            logger.debug("No more tests")
            self.send_message("stop")
        else:
            self.logger.test_start(test.id)
            self.send_message("run_test", test)

    def test_ended(self, test, results):
        #It would be nice to move this down into the runner
        file_result, test_results = results
        for result in test_results:
            if test.disabled_subtest(result.name, self.run_info):
                continue
            expected = test.expected_subtest(result.name, self.run_info) == result.status
            self.logger.test_result(test.id,
                                    result.name,
                                    result.status,
                                    message=result.message,
                                    unexpected=not expected)

        expected = test.expected_file(self.run_info) == file_result.status
        self.logger.test_end(test.id,
                             file_result.status,
                             message=file_result.message,
                             unexpected=not expected)
        #Restarting after a timeout is quite wasteful, but it seems otherwise we can get
        #results from the timed-out test back when we are waiting for the results of a
        #later test
        if file_result.status in ("TIMEOUT", "CRASH"):
            self.restart_runner()
        else:
            self.start_next_test()

    def setup_succeeded(self):
        self.init_timer.cancel()
        self.setup_fail_count = 0
        self.start_next_test()

    def setup_failed(self):
        self.init_timer.cancel()
        self.setup_fail_count += 1
        if self.setup_fail_count < self.max_setup_fails:
            self.restart_runner()
        else:
            return Stop

    def restart_runner(self):
        self.stop_runner(graceful=False)
        self.init()

    def on_output(self, line):
        self.logger.info(line, {"type":"firefox-output"})


class ManagerPool(object):
    def __init__(self, runner_cls, run_info, size, server_url, binary_path,
                 process_cls=FirefoxProcess):
        self.server_url = server_url
        self.binary_path = binary_path
        self.size = size
        self.runner_cls = runner_cls
        self.process_cls = process_cls
        self.pool = set()
        #Event that is polled by threads so that they can gracefully exit in the face
        #of sigint
        self.stop_flag = threading.Event()
        self.run_info = run_info
        signal.signal(signal.SIGINT, get_signal_handler(self))

    def start(self, tests_queue):
        used_ports = set()
        logger.debug("Using %i processes" % self.size)
        for i in range(self.size):
            marionette_port = get_free_port(2828, exclude=used_ports)
            used_ports.add(marionette_port)
            manager = TestRunnerManager(self.server_url,
                                        self.binary_path,
                                        self.run_info,
                                        tests_queue,
                                        self.stop_flag,
                                        runner_cls=self.runner_cls,
                                        marionette_port=marionette_port,
                                        process_cls=self.process_cls)
            manager.start()
            self.pool.add(manager)

    def is_alive(self):
        for manager in self.pool:
            if manager.is_alive():
                return True
        return False

    def wait(self):
        for item in self.pool:
            item.join()

    def stop(self):
        self.stop_flag.set()


def load_manifest(test_root):
    sys.path.insert(0, os.path.join(test_root, "tools", "scripts"))
    import manifest

    mainfest_path = os.path.abspath(os.path.join(os.path.split(__file__)[0],
                                                 "metadata", "MANIFEST.json"))

    manifest.setup_git(test_root)
    test_manifest = manifest.load(mainfest_path)
    manifest.update(test_manifest)
    return test_manifest

def load_expected(test):
    expected_root = os.path.join(os.path.split(__file__)[0], "metadata")
    expected_path = os.path.join(expected_root, test.path + ".ini")
    if not os.path.exists(expected_path):
        expected_data = {}
    else:
        expected_data = expected.parse(expected_root, expected_path)
    return expected_data


def queue_tests(test_root, test_types, run_info, include_filters):
    tests_by_type = defaultdict(Queue)

    test_manifest = load_manifest(test_root)

    for test_type in test_types:
        for test in test_manifest.itertype(test_type):
            queue_test = False
            if include_filters:
                for filter_str in include_filters:
                    if test.url.startswith(filter_str):
                        queue_test = True
            else:
                queue_test = True
            if queue_test:
                expected = load_expected(test)
                test = construct_test(test, expected)
                if not test.disabled(run_info):
                    tests_by_type[test_type].put(test)

    return tests_by_type


def abs_path(path):
    return os.path.abspath(path)


def parse_args():
    parser = argparse.ArgumentParser(description="Runner for web-platform-tests tests.")
    parser.add_argument("binary", action="store",
                        type=abs_path,
                        help="Binary to run tests against")
    parser.add_argument("tests_root", action="store", type=abs_path,
                        help="Path to web-platform-tests")
    parser.add_argument("--server", action="store", type=abs_path,
                        default=os.path.join(".", "wptserve", "wptserve.py"),
                        help="Path to web-platform-tests server")
    parser.add_argument("--test-types", action="store",
                        nargs="*", default=["testharness"],
                        choices=test_runner_classes.keys(),
                        help="Test types to run")
    parser.add_argument("--test", action="store", type=abs_path,
                        help="Path to specific test folder or manifest to use")
    parser.add_argument("--processes", action="store", type=int, default=1,
                        help="Number of simultaneous processes to use")
    parser.add_argument("--xvfb", action="store_true",
                        help="Run processes that require the display under xvfb")
    parser.add_argument("--stream", action="store", type=int, default=1234,
                        help="Stream the log messages to a port")
    parser.add_argument("--include", action="append", help="URL prefix to include")
    parser.add_argument("-o", dest="output_file", action="store", help="File to write output to")
    rv = parser.parse_args()
    if rv.test is None:
        rv.test = rv.tests_root
    return rv


def get_signal_handler(manager_pool):
    def sig_handler(signum, frame):
        logger.info("Got interrupt")
        manager_pool.stop()
    return sig_handler

test_runner_classes = {"reftest": ReftestTestRunner,
                       "testharness": TestharnessTestRunner}

def main():
    t0 = time.time()
    args = parse_args()

    if args.output_file:
        f = open(args.output_file, "w")
    else:
        f = sys.stderr
    logger.add_handler(structuredlog.StreamHandler(f))

    # if args.stream:
    #     socket_handler = structuredlog.SocketHandler("127.0.0.1", args.stream)
    #     logger.handlers.append(socket_handler)

    pr = cProfile.Profile()
    pr.enable()

    run_info = RunInfo(False)

    server_manager = start_http_server(args.server, args.tests_root)
    try:
        test_queues = queue_tests(args.tests_root, args.test_types, run_info,
                                  args.include)
        logger.tests_start(reduce(lambda x, y: x + y.qsize(), test_queues.itervalues(), 0))
        for test_type in args.test_types:
            tests_queue = test_queues[test_type]
            runner_cls = test_runner_classes[test_type]

            process_cls = FirefoxProcess
            if args.xvfb:
                process_cls = XvfbWrapped(process_cls)


            pool = ManagerPool(runner_cls,
                               run_info,
                               args.processes,
                               server_manager.proc.url,
                               args.binary,
                               process_cls=process_cls)
            pool.start(tests_queue)
            pool.wait()
        logger.tests_end()
    finally:
        server_manager.stop()
        pr.disable()
        pr.dump_stats("profile.stats")
        stats = pstats.Stats("profile.stats")
        stats.sort_stats("cumtime")
        stats.print_callers(5)

if __name__ == "__main__":
    main()
