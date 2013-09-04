import os

import manifestparser
from manifestparser import ManifestParser

class ExpectedManifestParser(ManifestParser):
    def __init__(self, root_dir):
        ManifestParser.__init__(self)
        self.rootdir = root_dir

    def _read(self, root, filename, defaults):
        # get directory of this file
        ini_path = os.path.abspath(filename)
        print root, ini_path
        path, ext = os.path.splitext(ini_path)
        assert ext == ".ini"
        
        # read the configuration
        sections = manifestparser.read_ini(fp=filename, variables=defaults, strict=self.strict)

        for section, data in sections:
            if "here" in data:
                del data["here"]

            if section.startswith("include:"):
                raise Exception("include sections not permitted")

            test = data
            test['name'] = section

            self.tests.append(test)

def parse(root_dir, filename, parser=None):
    if parser is None:
        parser = ExpectedManifestParser(root_dir)
    elif parser.rootdir != root_dir:
        raise ValueError

    parser.read(filename)
    tests = dict((item["name"], item) for item in parser.tests)
    parser.tests = []
    return tests
