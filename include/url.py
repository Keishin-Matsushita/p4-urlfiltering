#!/usr/bin/env python3

import sys

URL_BYTES = 256
URL_BYTES_1 = 255
URL_BITS =(URL_BYTES*8)

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

        exacts.append( '\t// %s://%s:%d%s' % (scheme,ip,port,url) )
        exacts.append( '\t(' )
        exacts.append( '\t\t%s,%d,' % (ipaddr,port) )
        s = '0x'
        for i in range(l):
            s = s + ('%02x' % (ord(url[i])))
        for i in range(URL_BYTES-l):
            s = s + '00'
        exacts.append( '\t\t%s' % (s) )
        exacts.append( '\t):act_http_url_match();' )

    elif kind == 'lpm':

        lpms.append( '\t// %s://%s:%d%s' % (scheme,ip,port,url) )
        lpms.append( '\t(' )
        lpms.append( '\t\t%s,%d,' % (ipaddr,port) )
        s = '0x'
        mask = '0x'
        for i in range(l):
            s = s + ('%02x' % (ord(url[i])))
            mask = mask + 'ff'
        for i in range(URL_BYTES-l):
            s = s + '00'
            mask = mask + '00'
        lpms.append( '\t\t%s' % (s) )
        lpms.append( '\t\t&&&' )
        lpms.append( '\t\t%s' % (mask) )
        lpms.append( '\t):act_http_url_match();' )




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
    if len(exacts) > 0:
        f.write( 'const entries = {\n' )
        f.write( '\n'.join( exacts ) )
        f.write( '\n}\n' )

with open( 'url_lpm.p4',mode='w' ) as f:
    if len(lpms) > 0:
        f.write( 'const entries = {\n' )
        f.write( '\n'.join( lpms ) )
        f.write( '\n}\n' )

with open( 'ports.p4',mode='w' ) as f:
    for (ipaddr,port) in group.keys():
        f.write( '\t(0,%s,%d): parse_http_init;\n' % (ipaddr,port) )

with open( 'define.p4',mode='w' ) as f:

    maxi = int(URL_BYTES/10)
    modi = int(URL_BYTES % 10)

    for i in [0,1]:
        for j in range(URL_BYTES):
            f.write( '#define NUMADD_%d_%d %d\n' % (i,j,i+j) )
    f.write( '\n' )

    f.write( '#define ZEROFILL(item,idx)  \\\n' )
    f.write( '\titem[idx].setValid();   \\\n' )
    f.write( '\titem[idx].ch = 0;       \\\n' )
    f.write( '\titem[idx].setInvalid()\n' )
    f.write( '\n' )

    f.write( '#define ZEROFILL10(a,idx)   \\\n' )
    f.write( '\tZEROFILL(a,idx);        \\\n' )
    f.write( '\tZEROFILL(a,idx+1);      \\\n' )
    f.write( '\tZEROFILL(a,idx+2);      \\\n' )
    f.write( '\tZEROFILL(a,idx+3);      \\\n' )
    f.write( '\tZEROFILL(a,idx+4);      \\\n' )
    f.write( '\tZEROFILL(a,idx+5);      \\\n' )
    f.write( '\tZEROFILL(a,idx+6);      \\\n' )
    f.write( '\tZEROFILL(a,idx+7);      \\\n' )
    f.write( '\tZEROFILL(a,idx+8);      \\\n' )
    f.write( '\tZEROFILL(a,idx+9)\n' )
    f.write( '\n' )

    f.write( '#define ZEROFILLMAX(a)   \\\n' )
    for i in range(maxi):
        f.write( '\tZEROFILL10(a,%d);     \\\n' % (i*10) )
    if modi != 0:
        for i in range(modi-1):
            f.write( '\tZEROFILL(a,%d);     \\\n' % (maxi*10+i) )
        f.write( '\tZEROFILL(a,%d)\n' % (maxi*10+modi-1) )
    f.write( '\n' )

    f.write( '#define TRANS_PARSE_URL_SHIFT(num,add) \\\n' )
    f.write( '\tNUMADD_##num##_##add : parse_url_shift_##num##_##add\n' )
    f.write( '\n' )

    f.write( '#define PARSE_URL_SHIFT(num,add) \\\n' )
    f.write( 'state parse_url_shift_##num##_##add \\\n' )
    f.write( '{ \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\tmeta.ch = meta.ch << (NUMADD_##num##_##add); \\\n' )
    f.write( '\ttransition parse_url_shift_done; \\\n' )
    f.write( '}\n' )

    f.write( '#define TRANS_PARSE_URL_SHIFT_MAX() \\\n' )
    for i in range(URL_BYTES-2):
        f.write( '\tTRANS_PARSE_URL_SHIFT(1,%d); \\\n' % (i) )
    f.write( '\tTRANS_PARSE_URL_SHIFT(1,%d)\n' % (URL_BYTES-1) )
    f.write( '\n' )

    f.write( '#define PARSE_URL_SHIFT10(num) \\\n' )
    for i in range(10):
        f.write( '\tPARSE_URL_SHIFT(num,%d) \\\n' % (i) )
    f.write( '\n' )

    f.write( '#define PARSE_URL_SHIFT_MAX() \\\n' )
    if maxi > 0:
        for i in range(URL_BYTES-2):
            f.write( '\tPARSE_URL_SHIFT(%d,%d) \\\n' % (1,i) )
        f.write( '\tPARSE_URL_SHIFT(%d,%d)' % (1,URL_BYTES-1) )
        f.write( '\n' )

