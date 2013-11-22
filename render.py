 # -*- coding: utf-8 -*-
import sys
import json
from cgi import escape
from collections import OrderedDict, defaultdict
import types

page_template = u"""<title>Web Platform Tests Results</title>
<meta charset=utf8>
<script src=render.js></script>
<script src=sorttable.js></script>
<h1>Web Platform Tests Results</h1>
<style>
.condition {color:white}
.OK, .PASS {background-color:green}
.FAIL {background-color:red}
.ERROR {background-color:blue}
.NOTRUN {background-color:purple}
.TIMEOUT {background-color:orange}
.CRASH {background-color:black}
.MISSING {background-color:pink}
.child {display:none}
</style>
<p>Ran %(num_tests)s of %(expected_num_tests)s expected in %(minutes)s minutes %(seconds)s seconds, efficiency %(efficiency).2f</p>
<p><label>Local server port <input name=local_port id=local_port value=8000></label></p>

<table id="conditions">
<tr><th colspan=2>Show parent conditions
<tr><td><input type="checkbox" name=condition_OK id=condition_OK checked><td class="condition OK">OK<td class=count id="count_OK">
<tr><td><input type="checkbox" name=condition_ERROR id=condition_ERROR checked><td class="condition ERROR">ERROR<td class=count id="count_ERROR">
<tr><td><input type="checkbox" name=condition_TIMEOUT id=condition_FAIL checked><td class="condition TIMEOUT">TIMEOUT<td class=count class=count id="count_TIMEOUT">
<tr><td><input type="checkbox" name=condition_CRASH id=condition_CRASH checked><td class="condition CRASH">CRASH<td class=count id="count_CRASH">
</table>

<table class=sortable id=results>
<tr><th><th>Parent test<th>Parent Status<th>Child pass rate<th>Duration (s)<th>Message</tr>
%(rows)s
</table>
"""

row_template = u"""<tr class="parent" data-parent-id="%(id)s"><td><td><a class="local_link" href="http://web-platform.test%(test)s">%(test)s</a> (<a href="http://w3c-test.org/web-platform-tests/master%(test)s">w3c-test.org</a>) <td class="condition %(parent_status)s parent">%(parent_status)s<td class="condition %(child_status)s">%(num_passes)d / %(num_children)d<td>%(duration).2f<td>%(message)s"""

child_template = u"""<tr class="child child_%(suffix)s"><td><td>%(name)s<td class="condition %(status)s">%(status)s<td><td><td>%(message)s"""

def load(fn):
    with open(fn) as f:
        rv = []
        for line in f:
            if not line.strip():
                continue
            try:
                rv.append(json.loads(line.strip()))
            except:
                print >> sys.stderr, line
        return rv

def get_data(data):
    rows = OrderedDict()
    start_time = None
    end_time = None
    expected_num_tests = None
    last_entry_time = data[-1]["time"]
    parent_id = [0]
    def create_row(item, expected):
        if "test" not in item:
            sys.stderr.write(json.dumps(item) + "\n")
            return
        if item["test"] not in rows:
            rows[item["test"]] = {"test":item["test"],
                                  "num_passes":0,
                                  "parent_status": "MISSING",
                                  "child_status": "MISSING",
                                  "message": "",
                                  "start_time": 0,
                                  "duration": 0,
                                  "tests": [],
                                  "id": parent_id[0]}
            parent_id[0] += 1
            if not expected:
                sys.stderr.write("Logs out of order for test %s\n" % item["test"])
        else:
            if expected:
                sys.stderr.write("Logs out of order for test %s\n" % item["test"])
        return rows[item["test"]]
    for item in data:
        if item["action"] == "test_start":
            current_row = create_row(item, True)
            current_row["start_time"] = item["time"]
        elif item["action"] == "test_end":
            current_row = create_row(item, False)
            current_row["parent_status"] = item["status"]
            current_row["num_children"] = len(current_row["tests"])
            current_row["child_status"] = "PASS" if current_row["num_passes"] == current_row["num_children"] and current_row["num_children"] > 0 else "FAIL"
            current_row["duration"] = (item["time"] - current_row["start_time"]) / 1000.
            current_row["message"] = item.get("message", "")
        elif item["action"] == "test_status":
            current_row = create_row(item, False)
            current_row["tests"].append({"name": item["subtest"],
                                         "status": item["status"],
                                         "message": item.get("message", "")})
            if item["status"] == "PASS":
                current_row["num_passes"] += 1
        elif item["action"] == "suite_start":
            start_time = item["time"]
            expected_num_tests = len(item["tests"])
        elif item["action"] == "suite_end":
            end_time = item["time"]

    if end_time is None:
        end_time = last_entry_time
    time_delta = (end_time - start_time) / 1000
    minutes = int(time_delta / 60)
    seconds = time_delta - minutes * 60

    return {"time":(minutes, seconds),
            "expected_num_tests": expected_num_tests,
            "tests": rows}

def main():
    rows = []
    data = get_data(load(sys.argv[1]))

    if "--html" in sys.argv:
        render_html(data)
    else:
        render_text(data)

def escape_dict(in_data):
    out_data = {}
    for key, value in in_data.iteritems():
        if type(value) in types.StringTypes:
            out_data[key] = escape(value)
        else:
            out_data[key] = value
    return out_data

def render_html(data):
    efficiency = sum(item["duration"] for item in data["tests"].itervalues()) / (data["time"][0] * 60 + data["time"][1])
    rows = []
    for item in data["tests"].itervalues():
        rows.append(row_template % escape_dict(item))
        # for child_item in item["tests"]:
        #     child_item.update({"suffix": item["id"]})
        #     rows.append(child_template % escape_dict(child_item))

    print (page_template % {"minutes":data["time"][0],
                            "seconds":data["time"][1],
                            "rows":"\n".join(rows),
                            "efficiency": efficiency,
                            "num_tests":len(data["tests"]),
                            "expected_num_tests":data["expected_num_tests"]}).encode("utf8")

def render_text(data):
    collected = defaultdict(list)
    for item in data["tests"].itervalues():
        collected[item["parent_status"]].append(item["test"])

    for status in sorted(collected.keys()):
        print "== %s ==" % status
        for value in sorted(collected[status]):
            print value
        print ""

if __name__ == "__main__":
    main()
