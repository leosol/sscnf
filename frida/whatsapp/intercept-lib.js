function doLog(filename){
	if(filename=='/dev/ashmem'){
		return;
	}
	console.log('filename =', filename);
}

Interceptor.attach(Module.findExportByName("/system/lib/libc.so", "open"), {
  onEnter: function(args) {
    this.flag = false;
    var filename = Memory.readCString(ptr(args[0]));
    doLog(filename);
    if (filename.endsWith(".xml")) {
      this.flag = true;
      var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
      console.log("file name [ " + Memory.readCString(ptr(args[0])) + " ]\nBacktrace:" + backtrace);
    }
  },
  onLeave: function(retval) {
    if (this.flag) // passed from onEnter
      console.warn("\nretval: " + retval);
  }
});