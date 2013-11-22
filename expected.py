import os
import sys
import copy
from collections import OrderedDict
import StringIO

class ManifestError(Exception):
    pass

def decode(byte_str):
    return byte_str.decode("string_escape").decode("utf8")

def encode(unicode_str):
    return unicode_str.encode("utf8").encode("string_escape")

def manifest_tokenizer(f):
    comment_chars = "#;"
    seperators = ":="

    for line in f:
        line = line.strip()

        if not line:
            continue

        elif line[0] in comment_chars:
            continue

        elif line.startswith("[") and line.endswith("]"):
            yield "section", decode(line[1:-1])

        for seperator in seperators:
            if seperator in line: #Need to deal with continuation lines and things also
                key, value = tuple(decode(part) for part in line.split(seperator, 1))
                yield "variable", (key, value)

class ExpectedData(object):
    def __init__(self, path=None):
        self.path = path
        self.data = OrderedDict()
        self.data["DEFAULT"] = OrderedDict()
        self.data["FILE"] = OrderedDict()

        self.reserved_names = ["DEFAULT", "FILE"]

    def __str__(self):
        return dumps(self)

    def add_subtest(self, name):
        if name in self.reserved_names:
            raise ValueError

        if name in self.data:
            raise ValueError("Duplicate subtest name")

        self.data[name] = OrderedDict()

    def remove_subtest(self, name):
        if name in self.reserved_names:
            raise ValueError
        del self.data[name]

    def has_subtest(self, name):
        if name is None:
            return True
        return name in self.data

    def set_default(self, key, value):
        if value is None:
            del self.data["DEFAULT"][key]
        else:
            self.default_data[key] = value

            if self.data.get(key) == value:
                del self.data[key]

            for subdata in self.subdata.itervalues():
                if subdata.get(key) == value:
                    del subdata[key]

    def set(self, subtest, key, value):
        if subtest in self.reserved_names:
            raise ValueError

        if subtest is None:
            subtest = "FILE"

        if subtest not in self.data:
            raise ValueError("Unknown subtest %s" % subtest)

        if value is None:
            del self.data[subtest][key]
            if (subtest not in self.reserved_names and not
                self.data[subtest]):
                self.remove_subtest(subtest)
        else:
            self.data[subtest][key] = value

    def set_test(self, key, value):
        self.set(None, key, value)

    def get(self, subtest=None, key=None, default=None):
        rv = self.data["DEFAULT"].copy()

        if subtest is None:
            rv.update(self.data["FILE"])
        else:
            rv.update(self.data.get(subtest, {}))

        if key is not None:
            return rv.get(key, default)
        else:
            return rv

    def copy(self):
        rv = ExpectedData(self.path)
        rv.data = copy.deepcopy(self.data)
        return rv

    def __iter__(self):
        for key in self.data.iterkeys():
            if self.data[key]:
                yield key

    def iter_variables(self, section):
        for key, value in self.data[section].iteritems():
            yield key, value

    def iter_subtests(self):
        for key in self.data.iterkeys():
            if key not in self.reserved_names:
                yield key

    def empty(self):
        return not any(self.data.itervalues())

def load(f, path=None):
    rv = ExpectedData(path)
    current_section = None
    for token_type, data in manifest_tokenizer(f):
        if token_type == "section":
            current_section = data

            if data not in ("FILE", "DEFAULT"):
                rv.add_subtest(data)

        elif token_type == "variable":
            key, value = data
            if current_section is None:
                raise ManifestError("Variable before section")
            elif current_section == "DEFAULT":
                rv.set_default(key, value)
            elif current_section == "FILE":
                rv.set(None, key, value)
            else:
                rv.set(current_section, key, value)
    return rv

def dump(data, f):
    for section in data:
        f.write("[%s]\n" % encode(section))
        for key, value in data.iter_variables(section):
            f.write("%s=%s\n" % (encode(key), encode(value)))
        f.write("\n")

def dumps(data):
    f = StringIO.StringIO()
    dump(data, f)
    return f.getvalue()
