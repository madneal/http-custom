##! Add an excerpt of HTTP POST bodies into the HTTP log.

@load base/protocols/http

module Corelight;

export {
	## The length of POST bodies to extract.
	const http_post_body_length = 200 &redef;
}

redef record HTTP::Info += {
	postdata: string &log &optional;
};

event log_post_bodies(f: fa_file, data: string)
	{
	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		if ( ! c$http?$postdata )
			c$http$postdata = "";

		# If we are already above the captured size here, just return.
		if ( |c$http$postdata| > http_post_body_length )
			return;

		c$http$postdata = c$http$postdata + data;
		if ( |c$http$postdata| > http_post_body_length )
			{
			c$http$postdata = c$http$postdata[0:http_post_body_length] + "...";
			# This is currently failing on Corelight Sensors to due to restrictions so 
			# we will work around it for now.
			#Files::remove_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
			}
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( is_orig && c?$http && c$http?$method && c$http$method == "POST" )
		{
		c$http$postdata = encode_base64(c$http$postdata)
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
		}
	}
