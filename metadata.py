import sys
import os

import expected

manifest = None

def do_test_relative_imports(test_root):
    global manifest

    sys.path.insert(0, os.path.join(test_root))
    sys.path.insert(0, os.path.join(test_root, "tools", "scripts"))
    import manifest

def load_manifest(test_root):
    if manifest is None:
        do_test_relative_imports(test_root)

    mainfest_path = os.path.abspath(os.path.join(os.path.split(__file__)[0],
                                                 "metadata", "MANIFEST.json"))

    manifest.setup_git(test_root)
    test_manifest = manifest.load(mainfest_path)
    manifest.update(test_manifest)
    return test_manifest


def load_expected(test):
    #This should work from the test URL not the path
    expected_root = os.path.join(os.path.split(__file__)[0], "metadata")
    expected_path = os.path.join(expected_root, test.path + ".ini")

    if not os.path.exists(expected_path):
        expected_data = expected.ExpectedData(expected_path)
    else:
        with open(expected_path) as f:
            expected_data = expected.load(f, expected_path)
    return expected_data
