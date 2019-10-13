@load base/protocols/http

module HTTP;

export {
    const http_post_body_length = 200 &redef;
}

redef record HTTP::Info += {
    post_body: string &log &optional;
}

event log_post_bodies(f: fa_file, data: string)
    {
        for ( cid in f$conns )
            {
                local c: connection = f$conns[cid];
                if ( ! c$http?$post_body )
                    c$http$post_body = "";
                
                if ( |c$http$post_body| > http_post_body_length )
                    {
                        c$http$post_body
                    }

                
            }
    }