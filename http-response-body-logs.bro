##! This script reassembles full HTTP bodies and raises an event with the
##! complete contents.

module HTTP;

export {
    redef record Info += {
       body: string &log &optional;
    };

    ## Flag that indicates whether to hook reply bodies.
    const hook_reply_bodies = T &redef;

    ## Do not buffer more than this amount of bytes per HTTP message.
    const max_body_size = 4096;
}

## Users write a handler for this event to process the current HTTP body.

event http_begin_entity(c: connection, is_orig: bool)
    {
    if ( (is_orig) || (! is_orig && ! hook_reply_bodies) )
        return;

    c$http$body = "";
    }

event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
    {
    if ( ! c$http?$body )
        return;

    c$http$body += data;
    if ( |c$http$body| > max_body_size )
	{
	c$http$body = c$http$body[0:max_body_size] + "...";
	}

    }

