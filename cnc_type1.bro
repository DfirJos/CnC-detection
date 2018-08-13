# -------------------------------------------------
# Bro script to detect Domain Fronted C&C channels |
# -------------------------------------------------

# C&C beacons are used to poll the C&C server for further instructions.
# These beacons often have a stream of packets sharing the same
# payload size which provides chances for detection. This script
# aims to detect C&C traffic leveraging the lack of payload
# size variance in a stream of TCP packets in a TCP flow.
#
# - Jos Clephas


module cnc_type1;

export {

	global conns:table[string] of count &redef;			# Tracks TCP flows
	global variance:table[string] of set[count] &redef;	# Stores unique payload sizes for each configured timeframe within each flow
	global timing:table[string] of count &redef;		# Stores timing information for resetting detection windows
	global log:table[string] of count &redef; 			# Tracks if flow is already printed

	const staging_process = 30;		# Time in seconds from each start of a TCP flow that needs to be ignored (aka staging process)
	const min_payloadsize = 85; 	# Minimum payload size in bytes
	const max_payloadsize = 1459; 	# Maximum payload size in bytes
	const max_variance = 3; 		# The maximum number of variances in payload size of each flow
	const timeframe = 300; 			# Timeframe in seconds in which detection takes place (0 for disabling interval)
	const min_packets = 40;			# The minimum number of packets that each timeframe of each flow should contain
   
	redef enum Log::ID += { LOG };

	type Info: record {
	
		start_time:				time &log;
        uid:					string &log;
		orig_h:					addr &log;
        orig_p: 				port &log;
		resp_h:					addr &log;	
		resp_p:					port &log;
		detection_window_start:	double &log;
		detection_window_end:	double &log;
		variance_payloadsizes:	count &log;
		counted_packets:		count &log;
		duration:				double &log;
		msg:					string &log;

	};
}

event bro_init() {

    Log::create_stream(LOG, [$columns=Info]);
	
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) { 
	
	local duration = interval_to_double(c$duration);
	
	if ( c$uid !in conns ) {
	
		conns[c$uid] = 0;
		variance[c$uid] = set();
		timing[c$uid] = timeframe;
		log[c$uid] = 0;
	}
	
	if ( is_orig == T && len >= min_payloadsize && len <= max_payloadsize && 
		 duration >= staging_process ) {

		conns[c$uid] += 1;
		
		add variance[c$uid][len];
		
		
		if ( duration >= timing[c$uid] && 
			 |variance[c$uid]| <= max_variance && conns[c$uid] >= min_packets) {
			
			Log::write( cnc_type1::LOG, [	
				
				$start_time=c$start_time,
				$uid=c$uid,
				$orig_h=c$id$orig_h, 
				$orig_p=c$id$orig_p, 
				$resp_h=c$id$resp_h, 
				$resp_p=c$id$resp_p,
				$detection_window_start=duration - timeframe + staging_process,
				$detection_window_end=duration,
				$variance_payloadsizes=|variance[c$uid]|,
				$counted_packets=conns[c$uid],
				$duration=duration,
				$msg="CnC channel detected based on the lack of payloadsize variance in sequence of packets throughout a TCP flow"
				
			]);
			
			# Below code-block makes sure only the first detected TCP flow will be displayed in the console
			if ( log[c$uid] == 0 ) {
				print fmt("Start time of flow: %s", c$start_time);
				print fmt("Flow ID %s:", c$uid);
				print fmt("orig_h: %s", c$id$orig_h);
				print fmt("orig_p: %s", c$id$orig_p);
				print fmt("resp_h: %s", c$id$resp_h);
				print fmt("resp_p: %s", c$id$resp_p);
				print fmt("Detection window: %s to %s", interval_to_double(c$duration) - timeframe + staging_process, c$duration);				
				print fmt("Different payload sizes: %s", variance[c$uid]);
				print fmt("Variance in payload size: %s", |variance[c$uid]|);
				print fmt("Counted packets: %s", conns[c$uid]);
				print fmt("Duration of flow: %s", c$duration);
				print fmt("Note: only the first detected suspicious flow is displayed here.");
				print "----";
			}			
		}
		
		# Below code-block is to make sure that the detection window resets itself every x seconds (configured with var: timeframe.)
		if ( interval_to_double(c$duration) >= timing[c$uid] ) {
		
			timing[c$uid] += timeframe;
			conns[c$uid] = 0;
			delete variance[c$uid];
			variance[c$uid] = set();
			log[c$uid] += 1;
		}

		return;
	}
	
}

# Todo:
# - Built correlation