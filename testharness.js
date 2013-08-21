var win = window.open();
addEventListener("message", function(e) {
  if(e.data.type == "complete") {
    win.close();
    var test_results = e.data.tests.map(function(x) {
        return {name:x.name, status:x.status, message:x.message}
    });
    marionetteScriptFinished({tests:test_results, status: e.data.status.status});
  }
}, false);
win.location = "%s";
