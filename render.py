import sys
import json
from collections import OrderedDict

page_template = u"""<title>Web Platform Tests Results</title>
<h1>Web Platform Tests Results</h1>
<meta charset=utf8>
<script src=sorttable.js></script>
<style>
.condition {color:white}
.OK, .PASS {background-color:green}
.FAIL {background-color:red}
.ERROR {background-color:blue}
.NOTRUN {background-color:purple}
.TIMEOUT {background-color:orange}
.CRASH {background-color:black}
.MISSING {background-color:pink}
</style>
<p>Took %(minutes)s minutes %(seconds)s seconds, efficiency %(efficiency).2f</p>
<table class=sortable>
<tr><th>Parent test<th>Parent Status<th>Child pass rate<th>Duration (s)<th>Message</tr>
%(rows)s
</table>"""

row_template = u"""<tr><td><a href="http://w3c-test.org/web-platform-tests/master%(test)s">%(test)s</a><td class="condition %(parent_status)s">%(parent_status)s<td class="condition %(child_status)s">%(num_passes)d / %(num_children)d<td>%(duration).2f<td>%(message)s"""

def load(fn):
    with open(fn) as f:
        rv = []
        for line in f:
            if not line.strip():
                continue
            try:
                rv.append(json.loads(line.strip()))
            except:
                print line
        return rv

def get_data(data):
    rows = OrderedDict()
    start_time = None
    end_time = None
    last_entry_time = data[-1]["time"]
    def create_row(item, expected):
        if "test" not in item:
            sys.stderr.write(json.dumps(item) + "\n")
            return
        if item["test"] not in rows:
            rows[item["test"]] = {"test":item["test"],
                                  "num_children":0,
                                  "num_passes":0,
                                  "parent_status": "MISSING",
                                  "child_status": "MISSING",
                                  "message": "",
                                  "start_time": 0,
                                  "duration": 0}
            if not expected:
                sys.stderr.write("Logs out of order for test %s\n" % item["test"])
        else:
            if expected:
                sys.stderr.write("Logs out of order for test %s\n" % item["test"])
        return rows[item["test"]]
    for item in data:
        if item["action"] == "TEST-START":
            current_row = create_row(item, True)
            current_row["start_time"] = item["time"]
        elif item["action"] == "TEST-END":
            current_row = create_row(item, False)
            current_row["parent_status"] = item["status"]
            current_row["child_status"] = "PASS" if current_row["num_passes"] == current_row["num_children"] else "FAIL"
            current_row["duration"] = (item["time"] - current_row["start_time"]) / 1000.
            current_row["message"] = item.get("message", "")
        elif item["action"] == "TEST-RESULT":
            current_row = create_row(item, False)
            current_row["num_children"] += 1
            if item["status"] == "PASS":
                current_row["num_passes"] += 1
        elif item["action"] == "TESTS-START":
            start_time = item["time"]
        elif item["action"] == "TESTS-END":
            end_time = item["time"]

    if end_time is None:
        end_time = last_entry_time
    time_delta = (end_time - start_time) / 1000
    minutes = int(time_delta / 60)
    seconds = time_delta - minutes * 60

    return (minutes, seconds), rows

rows = []
time, row_data = get_data(load("results.json"))
efficiency = sum(item["duration"] for item in row_data.itervalues()) / (time[0] * 60 + time[1])
for item in row_data.itervalues():
    rows.append(row_template % item)

print (page_template % {"minutes":time[0], "seconds":time[1], "rows":"\n".join(rows),
                        "efficiency": efficiency}).encode("utf8")
