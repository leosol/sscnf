'use strict';
//frida --usb --load change-log-level.js --attach-frontmost com.whatsapp

if (Java.available) {
    console.log('Java Process!')

    Java.perform(function () {
        var Test = Java.use("com/whatsapp/util/Log");
        console.log('Current Log value:');
        console.log( Test.level.value );
        Test.level.value = 0;
        console.log('Confirm Log level is Zero:');
        console.log( Test.level.value );
		console.log('Completed!')
    });
} else {
    console.log("not Java Process!")    
}