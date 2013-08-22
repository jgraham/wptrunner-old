import sys
import os
import argparse
import urlparse
import time
import json
from Queue import Queue, Empty
from multiprocessing import Process, Pipe
import threading
import urllib2
import socket
import signal
import hashlib
from collections import defaultdict

import marionette
import mozprocess
from mozprofile.profile import Profile
from mozrunner import FirefoxRunner
import mozlog

logger = mozlog.getLogger("web-platform-tests")
logger.setLevel(mozlog.DEBUG)

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
        except urllib2.URLError, e:
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

class TestRunner(object):
    def __init__(self, http_server_url, command_pipe, marionette_port=None):
        self.http_server_url = http_server_url
        self.command_pipe = command_pipe
        if marionette_port is None:
            marionette_port = get_free_port(2828)
        self.marionette_port = marionette_port
        self.timer = None
        self.logger = mozlog.getLogger("WPT Testrunner %i" % id(self))

    def setup(self):
        logger.debug("Connecting to marionette on port %i" % self.marionette_port)
        #Supporting multiple processes requires a choice of ports here
        self.browser = marionette.Marionette(host='localhost', port=self.marionette_port)
        self.browser.wait_for_port()
        self.browser.start_session()
        logger.debug("Marionette session started")
    
    def teardown(self):
        self.command_pipe.close()
        #Close the marionette session

    def run(self):
        self.setup()
        commands = {"run_test":self.run_test}
        try:
            while True:
                command, args = self.command_pipe.recv()
                if command == "stop":
                    break
                else:
                    commands[command](*args)
        finally:
            self.teardown()

    def run_test(self, test):
        assert len(self.browser.window_handles) == 1

        def timeout_func():
            self.send_message("timeout", test)

        self.timer = threading.Timer(DEFAULT_TIMEOUT + 10, timeout_func)
        self.timer.start()

        self.browser.navigate("about:blank")
        self.browser.set_script_timeout(DEFAULT_TIMEOUT * 1000)

        try:
            result = self.do_test(test)
        except marionette.errors.ScriptTimeoutException:
            result = {"status":"TIMEOUT", "tests": None}
            #Clean up any unclosed windows
            #This doesn't account for the possibility the browser window
            #is totally hung. That seems less likely since we are still
            #getting data from marionette, but it might be just as well
            #to do a full restart in this case
            #XXX - this doesn't work at the moment because window_handles
            #only returns OS-level windows (see bug 907197)
            while True:
                handles = self.browser.window_handles
                self.browser.switch_to_window(handles[-1])
                if len(handles) > 1:
                    self.browser.close()
                else:
                    break
            #Now need to check if the browser is still responsive and restart it if not
        except (socket.timeout, marionette.errors.InvalidResponseException):
            #This can happen on a crash
            #XXX Maybe better to have a specific crash message?
            #Also, should check after the test if the firefox process is still running
            #and otherwise ignore any other result and set it to crash
            result = {"status":"CRASH", "tests": None}
        finally:
            self.timer.cancel()
        self.send_message("test_ended", test, result)

    def do_test(self, test):
        raise NotImplementedError

    def send_message(self, command, *args):
        self.command_pipe.send((command, args))



class TestharnessTestRunner(TestRunner):
    def __init__(self, *args, **kwargs):
        TestRunner.__init__(self, *args, **kwargs)
        self.script = open("testharness.js").read()

    def do_test(self, test):
        url, = test
        return self.browser.execute_async_script(
            self.script % urlparse.urljoin(self.http_server_url, url))


class ReftestTestRunner(TestRunner):
    def __init__(self, *args, **kwargs):
        TestRunner.__init__(self, *args, **kwargs)
        with open("reftest.js") as f:
            self.script = f.read()
        self.ref_hashes = {}
        self.ref_urls_by_hash = defaultdict(set)

    def do_test(self, test):
        url, ref_type, ref_url = test
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

        return {"status":0, "tests":[{"status": 0 if passed else 1,
                                      "name": None}]}

    def teardown(self):
        count = 0
        for hash_val, urls in self.ref_urls_by_hash.iteritems():
            if len(urls) > 1:
                print "The following %i reference urls appear to be equivalent:\n " % len(urls), "\n  ".join(urls)
                count += len(urls) - 1
        print "In total %i screnshots could be avoided" % count
        TestRunner.teardown(self)


def start_runner(runner_cls, http_server_url, marionette_port, command_pipe):
    runner = runner_cls(http_server_url, command_pipe, marionette_port=marionette_port)
    runner.run()



class TestRunnerManager(threading.Thread):
    """Thread that owns a single TestRunner process and any processes required
    by the TestRunner (e.g. the Firefox binary)"""

    def __init__(self, server_url, firefox_binary, tests_queue, results_queue,
                 stop_flag, runner_cls=TestharnessTestRunner,
                 marionette_port=None):
        self.http_server_url = server_url
        self.firefox_binary = firefox_binary
        self.tests_queue = tests_queue
        self.results_queue = results_queue
        self.stop_flag = stop_flag
        self.command_pipe = None
        self.firefox_runner = None
        self.test_runner_proc = None
        self.runner_cls = runner_cls
        self.marionette_port = marionette_port
        threading.Thread.__init__(self)

    def run(self):
        self.init()
        while True:
            commands = {"test_ended":self.test_ended,
                        "timeout":self.timeout}
            has_data = self.command_pipe.poll(1)
            if has_data:
                command, data = self.command_pipe.recv()
                commands[command](*data)
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
        self.command_pipe, remote_end = Pipe()

        self.start_firefox()
        self.start_test_runner(remote_end)

        self.start_next_test()

    def start_firefox(self):
        env = os.environ.copy()
        env['MOZ_CRASHREPORTER_NO_REPORT'] = '1'

        profile = Profile()
        profile.set_preferences({"marionette.defaultPrefs.enabled": True,
                                 "marionette.defaultPrefs.port": self.marionette_port,
                                 "dom.disable_open_during_load": False})

        self.firefox_runner = FirefoxRunner(profile,
                                            self.firefox_binary,
                                            cmdargs=["--marionette"],
                                            env=env)
        self.firefox_runner.start()

    def start_test_runner(self, remote_connection):
        self.test_runner_proc = Process(target=start_runner,
                                        args=(self.runner_cls,
                                              self.http_server_url,
                                              self.marionette_port,
                                              remote_connection))
        self.test_runner_proc.start()

    def send_message(self, command, *args):
        self.command_pipe.send((command, args))

    def stop_runner(self, graceful=True):
        if graceful:
            self.test_runner_proc.join(10)
            if self.test_runner_proc.is_alive():
                graceful = False
        self.firefox_runner.stop()
        if not graceful:
            self.test_runner_proc.terminate()
        self.command_pipe.close()

    def start_next_test(self):
        try:
            test = self.tests_queue.get(False)
        except Empty:
            self.send_message("stop")
        else:
            self.send_message("run_test", test)

    def test_ended(self, url, results):
        self.results_queue.put((url, results))
        if results["status"] == "CRASH":
            self.restart_runner()
        self.start_next_test()

    def timeout(self, test_id):
        self.results_queue.put((test_id, {"status":"TIMEOUT", "tests":None}))
        self.restart_runner()

    def restart_runner(self):
        self.stop_runner(graceful=False)
        self.init()

class ManagerPool(object):
    def __init__(self, runner_cls, size, server_url, binary_path):
        self.server_url = server_url
        self.binary_path = binary_path
        self.size = size
        self.runner_cls = runner_cls
        self.pool = set()
        #Event that is polled by threads so that they can gracefully exit in the face
        #of sigint
        self.stop_flag = threading.Event()
        signal.signal(signal.SIGINT, get_signal_handler(self))

    def start(self, tests_queue):
        results_queue = Queue()
        used_ports = set()
        logger.debug("Using %i processes" % self.size)
        for i in range(self.size):
            print i
            marionette_port = get_free_port(2828, exclude=used_ports)
            print marionette_port
            used_ports.add(marionette_port)
            manager = TestRunnerManager(self.server_url,
                                        self.binary_path, 
                                        tests_queue,
                                        results_queue,
                                        self.stop_flag,
                                        runner_cls=self.runner_cls,
                                        marionette_port=marionette_port)
            manager.start()
            self.pool.add(manager)
            print "Started %i" % i
        return results_queue

    def is_alive(self):
        for manager in self.pool:
            if manager.is_alive():
                return True
        return False

    def stop(self):
        self.stop_flag.set()
        

def queue_tests(test_root, test_path, test_types):
    sys.path.insert(0, os.path.join(test_root, "tools", "scripts"))
    import update_manifest

    tests_by_type = defaultdict(Queue)

    if os.path.split(test_path)[1] == "MANIFEST":
        manifest = update_manifest.Manifest.from_file(test_path)
        tests_by_type = tests_from_manifest(manifest, test_types)
    else:
        for dirpath, dirnames, filenames in os.walk(test_path):
            if "MANIFEST" not in filenames:
                continue
            manifest = update_manifest.Manifest.from_file(test_root, 
                                                          os.path.join(dirpath, "MANIFEST"))
            manifest_tests = tests_from_manifest(manifest, test_types)
            for test_type, tests in manifest_tests.iteritems():
                for test in tests:
                    tests_by_type[test_type].put(test)

    return tests_by_type

def tests_from_manifest(manifest, test_types):
    tests_by_type = defaultdict(list)
    for test_type in test_types:
        for test in manifest.iter_type(test_type):
            test_url = "%s/%s" % (manifest.server_path, test["url"])
            if test_type == "reftest":
                ref_url = "%s/%s" % (manifest.server_path, test["ref_url"])
                test = (test_url, test["ref_type"], ref_url)
            else:
                test = (test_url,)
            tests_by_type[test_type].append(test)
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
    rv = parser.parse_args()
    if rv.test is None:
        rv.test = rv.tests_root
    return rv


def get_signal_handler(manager_pool):
    def sig_handler(signum, frame):
        manager_pool.stop()
    return sig_handler

test_runner_classes = {"reftest": ReftestTestRunner,
                       "testharness": TestharnessTestRunner}

def main():
    t0 = time.time()
    args = parse_args()
    

    server_manager = start_http_server(args.server, args.tests_root)

    test_queues = queue_tests(args.tests_root, args.test, args.test_types)

    
    print "Running %i test files" % reduce(lambda x, y: x + y.qsize(), test_queues.itervalues(), 0)
    with open("results.json", "w") as f:
        f.write("[\n")
        for test_type in args.test_types:
            tests_queue = test_queues[test_type]
            runner_cls = test_runner_classes[test_type]
            try:
                pool = ManagerPool(runner_cls, args.processes, server_manager.proc.url,
                                   args.binary)
                results_queue = pool.start(tests_queue)
                while True:
                    try:
                        result = results_queue.get(True, 1)
                    except Empty:
                        if not pool.is_alive():
                            break
                    else:
                        f.write(json.dumps(result) + ",\n")
            finally:
                server_manager.stop()
        f.write("]")

    
        print "Took %d" % (time.time() - t0)

if __name__ == "__main__":
    main()
