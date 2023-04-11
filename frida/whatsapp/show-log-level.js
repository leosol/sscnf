'use strict';
//frida -U --no-pause -l describe-class.js -f com.whatsapp

if (Java.available) {
    console.log('Java Process!')

    Java.perform(function () {
        var Test = Java.use("com/whatsapp/util/Log");
        console.log( Test.level.value );

    });
} else {
    console.log("not Java Process!")    
}