var proc = Module.findBaseAddress("libil2cpp.so")

console.log("[Frida Hook] Initiating hook at address 0x04851030!")
Interceptor.attach(proc.add(0x04851030), {
	onLeave: function (retval) {
        console.log("[Frida Hook] Replacing return value: " + retval + " -> 0x1")
        retval.replace(0x1)
    }
})

console.log("[Frida Hook] Initiating hook at address 0x023193ec!")
Interceptor.replace(proc.add(0x023193ec), new NativeCallback(function () {
    console.log("[Frida Hook] Redirecting OnUIStateChanged for pause glitch")
}, 'void', ['pointer']));

console.log("No bugs, all injected")