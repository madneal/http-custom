
module HTTP;

export {
    redef record Info += {
       http_end_time: time &optional;
       http_start_time: time &optional;
       http_response_time: double &log &optional;
    };

}

event http_message_done(c: connection, is_orig: bool, stat:  http_message_stat) &priority=20
    {
    if ( is_orig )
          c$http$http_start_time = stat$start;
    else
          {
          c$http$http_end_time = network_time();
          c$http$http_response_time = time_to_double(c$http$http_end_time) - time_to_double(c$http$http_start_time);
          }    
    }

