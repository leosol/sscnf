//00024a81 T Java_com_whatsapp_voipcalling_Voip_getCurrentCallState
//frida -U --no-pause -l .\hook-set-log-level-fn-ugglite.js -f com.whatsapp
var moduleName = "libwhatsapp.so"; 
//var setLogLevelAddr = 0x1BEFF4+0x1; 
//var getLogLevelAddr = 0x1BF000+0x1;

//ugglite
var setLogLevelAddr = 0x2931C0+0x0;
var getLogLevelAddr = 0x2931CC+0x0;

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            //console.log("Ret: " + retval);
			//var baseAddr = Module.findBaseAddress(moduleName);
            //Interceptor.attach(baseAddr.add(getLogLevelAddr), {
            //    onEnter: function(args) {
					
//					var memAddrSetLogLevelAddr = new NativePointer(baseAddr.add(setLogLevelAddr));
//					var fnSetLogLevelAddr = new NativeFunction(memAddrSetLogLevelAddr, 'uint32', ['uint32']);
//					var result = fnSetLogLevelAddr(10);
//					console.log('New log level set to ', result);
//                },
//				onLeave: function(retval){
//					console.log('Retval: ', retval);
//				}
//            });
		}
    }
});
