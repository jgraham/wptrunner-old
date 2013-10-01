window.wrappedJSObject.timeout_multiplier = 1;

function listener(e) {
    if(e.data.type == "complete") {
        clearTimeout(timer);
        removeEventListener("message", listener); 
        var test_results = e.data.tests.map(function(x) {
            return {name:x.name, status:x.status, message:x.message}
        });
        marionetteScriptFinished({test:"%(url)s",
                                  tests:test_results,
                                  status: e.data.status.status,
                                  message: e.data.status.message});
    }
}
addEventListener("message", listener, false);
window.wrappedJSObject.win = window.open("%(abs_url)s", "%(window_id)s");

var timer = setTimeout(function() {
    window.wrappedJSObject.win.timeout();
}, %(timeout)s);
