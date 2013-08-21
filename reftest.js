var win = window.open();
win.location = "%s";
win.addEventListener("load", function(e) {
    marionetteScriptFinished(true);
  }, false);
