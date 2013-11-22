DEFAULT_TIMEOUT = 10 #seconds
LONG_TIMEOUT = 60 #seconds

import structuredlog

import mozinfo
import metadata

logger = structuredlog.getOutputLogger("WPT")

class RunInfo(object):
    def __init__(self, debug):
        self.platform = mozinfo.info
        self.debug = debug

class Test(object):
    def __init__(self, url, expected, timeout=None, path=None):
        self.url = url
        self.expected = expected
        self.timeout = timeout
        self.path = path

    @property
    def id(self):
        return self.url

    def disabled(self, run_info, subtest=None):
        if subtest is None:
            subtest = "FILE"

        return self.expected.get(subtest=subtest, key="disabled") is not None

    def expected_status(self, run_info, subtest=None):
        if subtest is None:
            default = "OK"
        else:
            default = "PASS"
        return self.expected.get(subtest=subtest, key="status", default=default).upper()


class TestharnessTest(Test):
    @property
    def id(self):
        return self.url

class ManualTest(Test):
    @property
    def id(self):
        return self.url


class ReftestTest(Test):
    def __init__(self, url, ref_url, ref_type, expected, timeout=None, path=None):
        self.url = url
        self.ref_url = ref_url
        if ref_type not in ("==", "!="):
            raise ValueError
        self.ref_type = ref_type
        self.expected = expected
        self.timeout = timeout
        self.path = path

    @property
    def id(self):
        return self.url, self.ref_type, self.ref_url

def from_manifest(manifest_test):
    test_cls = {"reftest":ReftestTest,
                "testharness":TestharnessTest,
                "manual":ManualTest}[manifest_test.item_type]

    expected = metadata.load_expected(manifest_test)

    timeout = LONG_TIMEOUT if manifest_test.timeout == "long" else DEFAULT_TIMEOUT

    if test_cls == ReftestTest:
        return test_cls(manifest_test.url,
                        manifest_test.ref_url,
                        manifest_test.ref_type,
                        expected,
                        timeout=timeout,
                        path=manifest_test.path)
    else:
        return test_cls(manifest_test.url,
                        expected,
                        timeout=timeout,
                        path=manifest_test.path)
