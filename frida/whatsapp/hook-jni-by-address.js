//00026211 T Java_com_whatsapp_voipcalling_Voip_getVoipParam
//00026355 T Java_com_whatsapp_voipcalling_Voip_getVoipParamElemCount
//00026295 T Java_com_whatsapp_voipcalling_Voip_getVoipParamForCall
//000239ed T Java_com_whatsapp_voipcalling_Voip_inviteToGroupCall
//000260f5 T Java_com_whatsapp_voipcalling_Voip_isRxNetworkConditionerOn
//000260e9 T Java_com_whatsapp_voipcalling_Voip_isTxNetworkConditionerOn
//F03BC: %d: Local: %s, Remote: %s, priority: 0x%x 
//00000000000532f0 startcall 
//frida -U --no-pause -l .\hook-jni-by-address.js -f com.whatsapp
// replace module
// https://stackoverflow.com/questions/62835255/how-can-i-use-inject-my-own-so-by-frida-when-there-is-a-string-type
var moduleName = "libwhatsapp.so"; 
var nativeFuncAddr = 0x025249; // $ nm --demangle --dynamic libfoo.so | grep "Class::method("

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
	 	console.log("onleave: " + this.lib);
        if (this.lib.endsWith(moduleName)) {
            console.log("ret: " + retval);
            var baseAddr = Module.findBaseAddress(moduleName);
            Interceptor.attach(baseAddr.add(nativeFuncAddr), {
                onEnter: function(args) {
                    console.log("[-] hook invoked");
                    //console.log(JSON.stringify({
                    //    a1: args[1].toInt32(),
                    //    a2: Memory.readUtf8String(Memory.readPointer(args[2])),
                    //    a3: Boolean(args[3])
                    //}, null, '\t'));
                },
				onLeave: function(retval){
					console.log('Retval: ', retval);
				}
            });
        }
    }
});
