# Requires Bro-Osquery to be installed

module cnc_type2;

export {
   
	global conns:table[addr, port] of count &redef;			# Tracks connections based on destination IP and port
	global starttime:table[addr, port] of time &redef;		# Stores starttime of each cnc connection
	global variance:table[addr, port] of set[count] &redef;	# Stores unique payload sizes for each configured timeframe within each flow
	global timing:table[addr, port] of count &redef;		# Stores timing information for resetting detection windows
	global log:table[addr, port] of count &redef; 			# Tracks if flow is already printed

	const staging_process = 30;		# Time in seconds from each start of a TCP flow that needs to be ignored (aka staging process)
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
		starttime_cnc:			double &log;
		counted_packets:		count &log;
		duration:				interval &log;
		msg:					string &log;
		
	};
}

event bro_init() {

    Log::create_stream(LOG, [$columns=Info]);
	
}

event connection_state_remove(c: connection) {
	
	local resp_h: addr = c$id$resp_h;
	local resp_p: port = c$id$resp_p;
	
	if ( [resp_h, resp_p] !in conns ) {
	
		conns[resp_h, resp_p] = 0;
		starttime[resp_h, resp_p] = c$conn$ts;
		variance[resp_h, resp_p] = set();
		timing[resp_h, resp_p] = timeframe;
		log[resp_h, resp_p] = 0;
		
	}
	
	local starttime_cnc = time_to_double(starttime[resp_h, resp_p]);
	local starttime_flow = time_to_double(c$conn$ts);
	
	if ( starttime_flow >= staging_process + starttime_cnc) {

		conns[resp_h, resp_p] += 1;
		add variance[resp_h, resp_p][c$orig$size];
		
		if ( starttime_flow >= timing[resp_h, resp_p] + starttime_cnc && 
			 |variance[resp_h, resp_p]| <= max_variance && 
			 conns[resp_h, resp_p] >= min_packets ) {

			Log::write( cnc_type2::LOG, [	
			
				$start_time=c$start_time,
				$uid=c$uid,
				$orig_h=c$id$orig_h, 
				$orig_p=c$id$orig_p, 
				$resp_h=c$id$resp_h, 
				$resp_p=c$id$resp_p,
				$detection_window_start=(starttime_flow - timeframe) + staging_process,
				$detection_window_end=starttime_flow,
				$variance_payloadsizes=|variance[resp_h, resp_p]|,
				$starttime_cnc=starttime_cnc,
				$counted_packets=conns[resp_h, resp_p],
				$duration=c$duration,
				$msg="CnC channel detected based on the lack of variance in sizes of several TCP flows going to the same destination IP + port"
				
			]);
			
			# Below code-block makes sure only the first detected TCP flow will be displayed in the console
			if ( log[resp_h, resp_p] == 0 ) {
			
				print fmt("Suspicious TCP flow:");
				print fmt("orig_h: %s", c$id$orig_h);
				print fmt("orig_p: %s", c$id$orig_p);
				print fmt("resp_h: %s", c$id$resp_h);
				print fmt("resp_p: %s", c$id$resp_p);
				print fmt("Detection window: %s to %s", (starttime_flow - timeframe) + staging_process, starttime_flow);	
				print fmt("Variance in flow sizes: %s", variance[resp_h, resp_p]);
				print fmt("Variance in total TCP flow size: %s", |variance[resp_h, resp_p]|);
				print fmt("Starttime cnc channel: %s", starttime_cnc);
				print fmt("Counted packets: %s", conns[resp_h, resp_p]);
				print fmt("Duration of flow: %s", c$duration);			
				print fmt("Note: only the first detected suspicious connection is displayed here.");
				print "----";
			
			}
			
		}

		# Below code-block is to make sure that the detection window resets itself every x seconds (configured with var: timeframe.)
		if ( starttime_flow >= timing[resp_h, resp_p] + starttime_cnc ) {
			timing[resp_h, resp_p] += timeframe;
			conns[resp_h, resp_p] = 0;
			delete variance[resp_h, resp_p];
			variance[resp_h, resp_p] = set();
			log[resp_h, resp_p] += 1;
		
		}
		
		return;		
	}
	
}

