'use strict';
//frida -U --no-pause -l hook-to-string-and-trace.js -f com.whatsapp
//strings:
//'Remote: '
//voip_prefs.xml
Java.perform(function() {
  ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
    //console.log('[?] ' + i + ' = ' + clazz);
    var func = 'toString';
    Java.use(clazz)[func].implementation = function() {
      var ret = this[func]();
      if (ret.indexOf('latency') != -1) {
         //print stacktrace if return value contains specific string
         Java.perform(function() {
        	var jAndroidLog = Java.use("android.util.Log"), jException = Java.use("java.lang.Exception");
        	console.log( jAndroidLog.getStackTraceString( jException.$new() ) );
         }); 
      }   
      send('[' + i + '] ' + ret);
      return ret;
    }   
  }); 
});