#!/usr/bin/env python3

import sys

urls = [
    # kind    ipaddr        ports        uri
    [ 'exact','0x0a000002',(80),         '/index.html' ],
    [ 'exact','0x0a000003',(80,445,8000),'/hello.html' ],
    [ 'lpm',  '0x0a000002',(80,445),     '/include/'   ],
    [ 'lpm',  '0x0a000002',(80,445,8000),'/set/'       ]
]

exacts = []
lpms   = []
group  = {}

def output( kind,ipaddr,port,url ):

    l = len(url)

    indices = range(2, 10, 2)
    data = [str(int(ipaddr[x:x+2], 16)) for x in indices]
    ip = '.'.join(data)
    scheme = 'https' if port == 445 else 'http'

    if kind == 'exact':

        exacts.append( '// %s://%s:%d%s' % (scheme,ip,port,url) )
        exacts.append( '(' )
        exacts.append( '\t%s,%d,' % (ipaddr,port) )
        s = '0x'
        for i in range(l):
            s = s + ('%02x' % (ord(url[i])))
        for i in range(32-l):
            s = s + '00'
        exacts.append( '\t%s' % (s) )
        exacts.append( '):act_http_url_match();' )

    elif kind == 'lpm':

        lpms.append( '// %s://%s:%d%s' % (scheme,ip,port,url) )
        lpms.append( '(' )
        lpms.append( '\t%s,%d,' % (ipaddr,port) )
        s = '0x'
        mask = '0x'
        for i in range(l):
            s = s + ('%02x' % (ord(url[i])))
            mask = mask + 'ff'
        for i in range(32-l):
            s = s + '00'
            mask = mask + '00'
        lpms.append( '\t%s' % (s) )
        lpms.append( '\t&&&' )
        lpms.append( '\t%s' % (mask) )
        lpms.append( '):act_http_url_match();' )




for ui in range(len(urls)):

    kind,ipaddr,ports,url = urls[ui]

    if type(ports) == int:

        group[(ipaddr,ports)] = (ipaddr,ports)
        output( kind,ipaddr,ports,url )

    else:

        for port in ports:
            group[(ipaddr,port)] = (ipaddr,port)
            output( kind,ipaddr,port,url )



with open( 'url_exact.p4',mode='w' ) as f:
    f.write( '\n'.join( exacts ) )

with open( 'url_lpm.p4',mode='w' ) as f:
    f.write( '\n'.join( lpms ) )

with open( 'ports.p4',mode='w' ) as f:
    for (ipaddr,port) in group.keys():
        f.write( '\t(0,%s,%d): parse_http_init;\n' % (ipaddr,port) )


