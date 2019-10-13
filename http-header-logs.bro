##! Extract and include the header names used for each request in the HTTP
##! logging stream.  The headers in the logging stream will be stored in the
##! same order which they were seen on the wire.

@load base/protocols/http/main

module HTTP;

export {
	redef record Info += {
		## The vector of HTTP header names sent by the client.  No header 
		## values are included here, just the header names.
		header_host:    string  &log    &optional;
                header_accept:  string  &log    &optional;
                header_accept_charset:  string  &log    &optional;
                header_accept_encoding:  string  &log    &optional;
                header_accept_language:  string  &log    &optional;
                header_accept_ranges:  string  &log    &optional;
                header_authorization:  string  &log    &optional;
                header_connection:  string  &log    &optional;
                header_cookie:  string  &log    &optional;
                header_content_length:  string  &log    &optional;
                header_content_type:  string  &log    &optional;
                header_proxy_authorization:  string  &log    &optional;
		## The vector of HTTP header names sent by the server.  No header 
		## values are included here, just the header names.
		server_header_names:  vector of string &log &optional;

		server_header_values:  vector of string &log &optional;
	};
	
	## A boolean value to determine if client headers are to be logged.
	const log_client_header_names = T &redef;
	
	## A boolean value to determine if server headers are to be logged.
	const log_server_header_names = T &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
        {
        if ( ! c?$http )
                return;

        if ( is_orig )
                {
                if ( log_client_header_names )
                        {
				switch ( name ) {
                                case "HOST":
                                    c$http$header_host = value;
                                    break;
                                case "ACCEPT":
                                    c$http$header_accept = value;
                                    break;
                                case "ACCEPT-CHARSET":
                                    c$http$header_accept_charset = value;
                                    break;
                                case "ACCEPT-ENCODING":
				    c$http$header_accept_encoding = value;
                                    break;
                                case "ACCEPT-LANGUAGE":
                                    c$http$header_accept_language = value;
                                    break;
                                case "ACCEPT-RANGES":
                                    c$http$header_accept_ranges = value;
                                    break;
                                case "AUTHORIZATION":
                                    c$http$header_authorization = value;
                                    break;
                                case "CONNECTION":
                                    c$http$header_connection = value;
                                    break;
                                case "COOKIE":
                                    c$http$header_cookie = value;
                                    break;
                                case "CONTENT-LENGTH":
                                    c$http$header_content_length = value;
                                    break;
                                case "CONTENT-TYPE":
                                    c$http$header_content_type = value;
                                    break;
                                case "PROXY-AUTHORIZATION":
                                    c$http$header_proxy_authorization = value;
                                    break;
                                }
			}
                }
        else
                {
                if ( log_server_header_names )
                        {
                        if ( ! c$http?$server_header_names )
                                c$http$server_header_names = vector();
                        c$http$server_header_names[|c$http$server_header_names|] = name;
                        if ( ! c$http?$server_header_values )
                                c$http$server_header_values = vector();
                        c$http$server_header_values[|c$http$server_header_values|] = value;
                        }
                }
        }
