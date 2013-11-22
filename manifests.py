import sys
import os
import subprocess
from collections import defaultdict
import copy

import manifestparser

import structuredlog
import metadata
import test as test_
import expected

logger = structuredlog.getOutputLogger("wptrunner.manifests")

def git(command, *args):
    return subprocess.check_output(["git", command] + list(args),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def rev_range(rev_old, rev_new, symmetric=False):
    joiner = ".." if not symmetric else ".."
    return "".join([rev_old, joiner, rev_new])

def paths_changed(rev_old, rev_new):
    data = git("diff", "--name-status", rev_range(rev_old, rev_new))
    output = set(fields.strip() for fields in line.strip().split(" ", 1)
                 for line in data.split("\n") if line.strip())
    return output

def load_change_data(rev_old, rev_new):
    changes = paths_changed(rev_old, rev_new)
    rv = {}
    status_keys = {"M": "modified",
                   "A": "new",
                   "D": "deleted"}
    #TODO: deal with renames
    for item in changes:
        rv[item[1]] = status_keys[item[0]]
    return rv

class TestResults(object):
    def __init__(self, test):
        self.test = test
        self.subtest_statuses = {}
        self.status = None
        self.unexpected = None

def test_id(item):
    if isinstance(item, list):
        test_id = tuple(item)
    else:
        test_id = item
    return test_id

def load_results(log_data):
    rv = {}
    for item in structuredlog.action_filter(log_data, set(["test_start", "test_end", "test_status"])):
        if item["action"] == "test_start":
            id = test_id(item["test"])
            rv[id] = TestResults(id)
        elif item["action"] == "test_end":
            try:
                rv[test_id(item["test"])].status = item["status"]
                rv[test_id(item["test"])].unexpected = item.get("unexpected", False)
            except KeyError:
                print rv
        elif item["action"] == "test_status":
            rv[test_id(item["test"])].subtest_statuses[item["subtest"]] = (item["status"],
                                                                           item.get("unexpected", False))
    return rv

def update_expected(manifest, change_data, results):
    tests_needing_review = set()

    run_info = test_.RunInfo(False)

    for path, items in manifest:
        for manifest_item in items:
            if manifest_item.item_type in ("manual", "helper"):
                continue

            test = test_.from_manifest(manifest_item)

            if test.id in results:
                #XXX might want to allow this?
                assert not test.disabled(run_info)
                new_expected, review_needed  = get_new_expected(test,
                                                                run_info,
                                                                results[test.id],
                                                                change_data.get(test.path, "unchanged"))
                if review_needed:
                    tests_needing_review.add(test)
            #Need some run_info to pass in here
            elif test.disabled(run_info):
                new_expected = test.expected.copy()
            else:
                logger.error("Missing result for test %s" % (test.id,))
                new_expected = None


            expected_path = test.expected.path
            if os.path.exists(expected_path):
                os.unlink(expected_path)

            if new_expected is not None and not new_expected.empty():
                expected_dir = os.path.split(expected_path)[0]
                if not os.path.exists(expected_dir):
                    os.makedirs(expected_dir)

                with open(expected_path, "w") as f:
                    expected.dump(new_expected, f)

    return tests_needing_review

def get_new_expected(test, run_info, result, change_status):
    if change_status not in ["new", "modified", "unchanged"]:
        raise ValueError, "Unexpected change status"

    if change_status == "new":
        assert old_expected.empty()

    new_expected = test.expected.copy()

    review_needed = set_expected_status(new_expected, None, change_status,
                                        result.status, result.unexpected, "OK")


    for subtest_name, (status, unexpected) in result.subtest_statuses.iteritems():
        if not test.disabled(run_info, subtest_name):
            updated_unchanged = set_expected_status(new_expected, subtest_name,
                                                    change_status, status, unexpected)
            if updated_unchanged:
                review_needed = True
        else:
            #Ignore the new status, just keep whatever's already in the file
            pass


    #Remove tests that weren't run
    missing_tests = set()
    for subtest in new_expected.iter_subtests():
        if subtest not in result.subtest_statuses and not test.disabled(run_info, subtest):
            missing_tests.add(test_name)
            if change_status == "unchanged":
                review_needed = True

    for subtest in missing_tests:
        new_expected.remove_subtest(subtest)

    return new_expected, review_needed

def set_expected_status(new_expected, subtest_name, change_status, status,
                        unexpected, pass_status="PASS"):
    if unexpected:
        if status != pass_status:
            if not new_expected.has_subtest(subtest_name):
                new_expected.add_subtest(subtest_name)
            new_expected.set(subtest_name, "status", status)

        elif new_expected.has_subtest(subtest_name):
            new_expected.set(subtest_name, "status", None)

        return change_status != "unchanged"

    return False

def main(test_root, log, rev_old=None, rev_new="HEAD"):
    #Need a mapping between test urls and filesystem paths
    warnings = {}
    statuses = {}

    with open(log) as f:
        test_results = load_results(structuredlog.read_logs(f))

    manifest = metadata.load_manifest(test_root)
    if rev_old is not None:
        change_data = load_change_data(rev_old, rev_new)
    else:
        change_data = {}

    update_expected(manifest, change_data, test_results)

if __name__ == "__main__":
    main(*sys.argv[1:])

# Inputs
#   - Old SHA1, New SHA1, old expected results, run log (from build that was previously green)

# Outputs:
#   - New expected results

#Possibilities:
# * New test
#   - Use results as expected results

# Existing test
#  * Result is expected
#    - Use existing expected
#  * Test is disabled
#    * File unchanged
#      - Test wasn't run so no change
#    * File changed
#      - Notify so test can be reexamined
#      - Improves if we can also detect changes in helper files
#  * Result is changed
#    * File changed
#      - use new result
#    * File unchanged
#      - manual review

# Test removed
#  - Delete expected result

# Open issues
#
# - Results from multiple platforms/configurations
