/* ex: set ff=dos ts=2 et: */
/* $Id$ */
/*
 * Copyright 2011 Ryan Flynn
 * All rights reserved.
 */
/*
 * Distributed Hash Table
 *
 * UDP-based distributed file sharing traffic used by various systems, notably BitTorrent. Also Storm botnet.
 *
 * References:
 *
 *  #1 Distrubted Hash Table [web page]
 *     <URL: http://en.wikipedia.org/wiki/Distributed_hash_table> [Accessed Feb 28 2011]
 *  #2 DHT Protocol BEP 5 [web page]
 *     <URL: http://www.bittorrent.org/beps/bep_0005.html> [Accessed Feb 28 2011]
 */

#ifndef DHT_H
#define DHT_H

#include "types.h"

typedef struct {
  ptrlen t, y, q, ar;
  ptrlen_list args;
} dht_pkt;

// ping Query = {"t":"aa", "y":"q", "q":"ping", "a":{"id":"abcdefghij0123456789"}}
// 

/*

d1:rd2:id20:\x89Uq\x18\xad\xed\xb6\x12EU\x82\xe2\x1b\xb1\x07V\xed\xe9\xf7\xa1e1:t4:ap\xc6#1:v4:UT\\x971:y1:re
d
1:r
d
2:id
20:\x89Uq\x18\xad\xed\xb6\x12EU\x82\xe2\x1b\xb1\x07V\xed\xe9\xf7\xa1e1:t4:ap\xc6#1:v4:UT\\x971:y1:re

d1:ad2:id20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6je1:q4:ping1:t4:pn\x00\x001:v4:TR#\x9d1:y1:qe

"arguments"
"query"
"response"


d
  1:a   (arguments)
  d
    2:id
    20:dd\x7f\x09\x85G\x1c\x068M\xb79/\x82j\x82\xe7\xe0\xb6j
  e
  1:q    (query)
      4:ping
        1:t 4:pn\x00\x00       (transaction id)
        1:v 4:TR#\x9d          ()
        1:y 1:q                (type)
  e

*/

/*
 * DHT Queries <URL: http://www.bittorrent.org/beps/bep_0005.html#dht-queries>
 * ping
 *   query len=56 d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe
 *   response len=47 d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
 * find_node
 *   query len=92 d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe
 *   response len=65 d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:y1:re
 * get_peers
 *   query len=95 d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe
 *   response len=82 d1:rd2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe1:t2:aa1:y1:re
 * announce_peer
 *   query len=129 d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe
 *   response len=47 d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re
 */

#endif

