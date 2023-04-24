/**
 *	& 'C:\Python39\Scripts\frida.exe' -U --no-pause -l .\hook-fn-addresses-and-log.js -f com.whatsapp
 */

var moduleName = "libwhatsapp.so"; 
var nativeFuncAddr = 0x025249;
var nativeFuncAddrs = [
	/*[0x00026595, 'Java_com_whatsapp_voipcalling_Voip_notifyFailureToCreateAlternativeSocket'],
	[0x0002659b, 'Java_com_whatsapp_voipcalling_Voip_notifyLostOfAlternativeNetwork'],
	[0x000265b5, 'Java_com_whatsapp_voipcalling_Voip_onCallInterrupted'],
	[0x00028145, 'Java_com_whatsapp_voipcalling_Voip_processPipModeChange'],
	[0x000269c5, 'Java_com_whatsapp_voipcalling_Voip_refreshVideoDevice'],
	[0x000260ed, 'Java_com_whatsapp_voipcalling_Voip_rejectCall'],
	[0x00026169, 'Java_com_whatsapp_voipcalling_Voip_rejectCallWithoutCallContext'],
	[0x0002634d, 'Java_com_whatsapp_voipcalling_Voip_rejectPendingCall'],
	[0x000269d7, 'Java_com_whatsapp_voipcalling_Voip_rejectVideoUpgrade'],
	[0x000269c9, 'Java_com_whatsapp_voipcalling_Voip_requestVideoUpgrade'],
	[0x00025e95, 'Java_com_whatsapp_voipcalling_Voip_resendOfferOnDecryptionFailure'],
	[0x00025d89, 'Java_com_whatsapp_voipcalling_Voip_sendRekeyRequest'],
	[0x00027111, 'Java_com_whatsapp_voipcalling_Voip_setBatteryState'],
	[0x0002711b, 'Java_com_whatsapp_voipcalling_Voip_setScreenSize'],
	[0x0002674d, 'Java_com_whatsapp_voipcalling_Voip_setVideoDisplayPort'],
	[0x000267fd, 'Java_com_whatsapp_voipcalling_Voip_setVideoPreviewPort'],
	[0x0002687d, 'Java_com_whatsapp_voipcalling_Voip_setVideoPreviewSize'],
	[0x00025249, 'Java_com_whatsapp_voipcalling_Voip_startCall'],
	[0x00025509, 'Java_com_whatsapp_voipcalling_Voip_startGroupCall'],
	[0x000264b5, 'Java_com_whatsapp_voipcalling_Voip_startTestNetworkConditionWithAlternativeSocket'],
	[0x0002697d, 'Java_com_whatsapp_voipcalling_Voip_startVideoCaptureStream'],
	[0x00026885, 'Java_com_whatsapp_voipcalling_Voip_startVideoRenderStream'],
	[0x000269a1, 'Java_com_whatsapp_voipcalling_Voip_stopVideoCaptureStream'],
	[0x00026901, 'Java_com_whatsapp_voipcalling_Voip_stopVideoRenderStream'],
	[0x0002716d, 'Java_com_whatsapp_voipcalling_Voip_switchCamera'],
	[0x00026525, 'Java_com_whatsapp_voipcalling_Voip_switchNetworkWithAlternativeSocket'],
	[0x000263c5, 'Java_com_whatsapp_voipcalling_Voip_timeoutPendingCall'],
	[0x0002643d, 'Java_com_whatsapp_voipcalling_Voip_transitionToRejoining'],
	[0x000269dd, 'Java_com_whatsapp_voipcalling_Voip_turnCameraOff'],
	[0x000269e1, 'Java_com_whatsapp_voipcalling_Voip_turnCameraOn'],
	[0x0002659f, 'Java_com_whatsapp_voipcalling_Voip_updateNetworkMedium'],
	[0x000265a7, 'Java_com_whatsapp_voipcalling_Voip_updateNetworkRestrictions'],
	[0x000269e5, 'Java_com_whatsapp_voipcalling_Voip_videoOrientationChanged'],
	[0x000E64F0, 'print_local_remote_info_sub_E64F0'],
	[0x000E6300, 'update_cand_pairs_with_remote_E6300'],
	[0x000E672C, 'update_cand_pairs_with_local_E672C'],
	[0x000E680C, 'updated_priority_of_P2P_cand_pair_E680C'],
	[0x000D9D40, 'updated_priority_and_latency_from_user_for_relay_D9D40']
	[0x000E672C, 'update_cand_pairs_with_local_E672C'],
	[0x000DADC4, 'set_remote_relay_latencies_DADC4'],
	[0x000D9138, 'relay_resolver_D9138'],
	[0x000DADC4, 'set_remote_relay_latencies_DADC4'],
	[0x000AF8EC, 'handle_offer_ack_AF8EC'], 
	[0x000AC67C, 'handle_offer_AC67C'],
	[0x000AF1F8, 'handle_preaccept_AF1F8'],
	[0x000D8828, 'update_remote_candidate_D8828'],
	[0x000D87A4, 'update_remote_candidate_D87A4'],
	[0x000E68DC, 'handle_p2p_duplex_E68DC'],
	[0x000E6BC0, 'handle_p2p_incoming_E6BC0'],
	[0x000E68DC, 'handle_p2p_duplex_E68DC'],
	[0x000DFE7C, 'get_host_ip_DFE7C'],
	[0x000E0E98, 'sub_E0E98'],
	[0x000DFE7C, 'get_host_ip_DFE7C'],
	[0x000DA944, 'set_transport_protocol_tcp_DA944'],
	[0x000D8A64, 'set_transport_protocol_udp_D8A64']*/
	[0x000D76D0, 'data_through_relay_D76D0']
	
];

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if ( this.lib.endsWith(moduleName)) {
            console.log("Processing module: "+this.lib);
            var baseAddr = Module.findBaseAddress(moduleName);
			console.log("Module baseAddr: "+baseAddr);
			for(var  i=0;i<nativeFuncAddrs.length; i++){
				var currentAttachment = nativeFuncAddrs[i][0];
				var currentAttachmentDesc = nativeFuncAddrs[i][1];
				console.log("Processing: 0x"+currentAttachment.toString(16)+' '+currentAttachmentDesc);
				Interceptor.attach(baseAddr.add(currentAttachment), {
	                onEnter: function(args) {
	                    console.log("Enter: 0x"+currentAttachment+' '+currentAttachmentDesc);
	                },
					/*onLeave: function(retval) {
						console.log('\tRetval: ', retval);
						console.log("Leave: 0x"+currentAttachment+' '+currentAttachmentDesc);
					}*/
            	});
			}
        }else{
			console.log('Ignoring module: '+this.lib);
		}
    }
});
