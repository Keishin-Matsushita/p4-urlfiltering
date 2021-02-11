/* -*- P4_16 -*- */
//********************************************************************
//*    SOURCE: url.p4                                                *
//*   PURPOSE: URL Filterng by p4                                    *
//* FORMATTED: P4_16 v1model (16 SEP 2020 version)                   *
//*   WRITTEN: 2021/02/09 Matsushita "spicy" Keishin                 *
//*  REVISION: 0.011 2021/02/11                                      *
//********************************************************************

#include <core.p4>
#include <v1model.p4>

// CONST VALUES
const bit<16> TYPE_ARP  = 0x806;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP = 6;

// H E A D E R S --------------------------------------------------------

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t 
{
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t 
{
    bit<16>   ht;
    bit<16>   pt;
    bit<8>    hlen;
    bit<8>    plen;
    bit<16>   op;
    macAddr_t srcAddr;
    ip4Addr_t srcIpAddr;
    macAddr_t dstAddr;
    ip4Addr_t dstIpAddr;
}

header ipv4_t 
{
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t 
{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_opt_t 
{
    varbit<320> option;
}

header char_t
{
    bit<8> ch;
}

struct headers 
{
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    tcp_t        tcp;
    tcp_opt_t    tcp_opt;
    char_t[10]   http_proto;     // GET,POST,DELETE  HTTP PROTOCOL
    char_t[10]   http_proto_sep; // ' '              HTTP PROTOCOL SPECE
    char_t[32]   http_url;       // /index.html      HTTP URL MAX LENGTH 32
    char_t[32]   http_url_tag;   // ?id=20           HTTP URL TAG ?,#
    char_t[10]   http_url_sep;   // ' '              HTTP URL SPECE
    char_t[10]   http_version;   // HTTP/1.1         HTTP VERSION
}

struct metadata 
{
    bit<16>     proto_len;
    bit<16>     proto_sep_len;
    bit<16>     url_len;
    bit<16>     url_tag_len;
    bit<16>     url_sep_len;
    bit<16>     version_len;
    bit<256>    url;
    bit<256>    ch;
    bit<16>     ch_url_len;
    bit<8>      mid;
    bit<1>      url_isvalid;
}





#define ZEROFILL(item,idx)  \
    item[idx].setValid();   \
    item[idx].ch = 0;       \
    item[idx].setInvalid()

#define ZEROFILL10(a,idx)   \
    ZEROFILL(a,idx);        \
    ZEROFILL(a,idx+1);      \
    ZEROFILL(a,idx+2);      \
    ZEROFILL(a,idx+3);      \
    ZEROFILL(a,idx+4);      \
    ZEROFILL(a,idx+5);      \
    ZEROFILL(a,idx+6);      \
    ZEROFILL(a,idx+7);      \
    ZEROFILL(a,idx+8);      \
    ZEROFILL(a,idx+9)


#define NUMADD_0_0 0
#define NUMADD_0_1 1
#define NUMADD_0_2 2
#define NUMADD_0_3 3
#define NUMADD_0_4 4
#define NUMADD_0_5 5
#define NUMADD_0_6 6
#define NUMADD_0_7 7
#define NUMADD_0_8 8
#define NUMADD_0_9 9
#define NUMADD_1_0 1
#define NUMADD_1_1 2
#define NUMADD_1_2 3
#define NUMADD_1_3 4
#define NUMADD_1_4 5
#define NUMADD_1_5 6
#define NUMADD_1_6 7
#define NUMADD_1_7 8
#define NUMADD_1_8 9
#define NUMADD_1_9 10
#define NUMADD_10_0 10
#define NUMADD_10_1 11
#define NUMADD_10_2 12
#define NUMADD_10_3 13
#define NUMADD_10_4 14
#define NUMADD_10_5 15
#define NUMADD_10_6 16
#define NUMADD_10_7 17
#define NUMADD_10_8 18
#define NUMADD_10_9 19
#define NUMADD_11_0 11
#define NUMADD_11_1 12
#define NUMADD_11_2 13
#define NUMADD_11_3 14
#define NUMADD_11_4 15
#define NUMADD_11_5 16
#define NUMADD_11_6 17
#define NUMADD_11_7 18
#define NUMADD_11_8 19
#define NUMADD_11_9 20
#define NUMADD_20_0 20
#define NUMADD_20_1 21
#define NUMADD_20_2 22
#define NUMADD_20_3 23
#define NUMADD_20_4 24
#define NUMADD_20_5 25
#define NUMADD_20_6 26
#define NUMADD_20_7 27
#define NUMADD_20_8 28
#define NUMADD_20_9 29
#define NUMADD_21_0 21
#define NUMADD_21_1 22
#define NUMADD_21_2 23
#define NUMADD_21_3 24
#define NUMADD_21_4 25
#define NUMADD_21_5 26
#define NUMADD_21_6 27
#define NUMADD_21_7 28
#define NUMADD_21_8 29
#define NUMADD_21_9 30
#define NUMADD_30_0 30
#define NUMADD_30_1 31
#define NUMADD_31_0 31

#define TRANS_PARSE_URL_SHIFT(num,add)      					\
        NUMADD_##num##_##add : parse_url_shift_##num##_##add

#define PARSE_URL_SHIFT(num,add)                         \
    state parse_url_shift_##num##_##add                  \
    {                                                    \
        meta.ch = meta.ch << ((NUMADD_##num##_##add)*8); \
        transition parse_url_shift_done;                 \
    }

#define TRANS_PARSE_URL_SHIFT10(num)     \
        TRANS_PARSE_URL_SHIFT(num,0);    \
        TRANS_PARSE_URL_SHIFT(num,1);    \
        TRANS_PARSE_URL_SHIFT(num,2);    \
        TRANS_PARSE_URL_SHIFT(num,3);    \
        TRANS_PARSE_URL_SHIFT(num,4);    \
        TRANS_PARSE_URL_SHIFT(num,5);    \
        TRANS_PARSE_URL_SHIFT(num,6);    \
        TRANS_PARSE_URL_SHIFT(num,7);    \
        TRANS_PARSE_URL_SHIFT(num,8);    \
        TRANS_PARSE_URL_SHIFT(num,9)

#define PARSE_URL_SHIFT10(num)     \
        PARSE_URL_SHIFT(num,0)     \
        PARSE_URL_SHIFT(num,1)     \
        PARSE_URL_SHIFT(num,2)     \
        PARSE_URL_SHIFT(num,3)     \
        PARSE_URL_SHIFT(num,4)     \
        PARSE_URL_SHIFT(num,5)     \
        PARSE_URL_SHIFT(num,6)     \
        PARSE_URL_SHIFT(num,7)     \
        PARSE_URL_SHIFT(num,8)     \
        PARSE_URL_SHIFT(num,9)






// P A R S E R -----------------------------------------------------------

parser UrlParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) 
{

    state start
    { 
        transition parse_ethernet;
    }

    state parse_ethernet
    {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) 
        {
            TYPE_ARP:  parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp
    {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4
    {
        packet.extract(hdr.ipv4);
        meta.url_isvalid = 0;
        transition select(hdr.ipv4.protocol)
        {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp
    {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dataOffset)
        {
            5: parse_tcp_port;
            default: parse_tcp_option;
        }
    }

    state parse_tcp_option
    {
        bit<32> opt_size = ((bit<32>)hdr.tcp.dataOffset) * 32 - 160;
        packet.extract(hdr.tcp_opt,opt_size);
        transition parse_tcp_port;
    }

    state parse_tcp_port
    {
        bit<8> flags = hdr.tcp.flags & 0x23;
        transition select(flags,hdr.ipv4.dstAddr,hdr.tcp.dstPort)
        {
            // PARSE TARGET DST PORT
#include "include/ports.p4"
            default: accept;
        }
    }

    // CLEAR URL DATA 0 FILLING
    state parse_http_init
    {
        // INITIALZIE http url info
        meta.proto_len     = 0;
        meta.proto_sep_len = 0;
        meta.url_len       = 0;
        meta.url_tag_len   = 0;
        meta.url_sep_len   = 0;
        meta.version_len   = 0;

        ZEROFILL10(hdr.http_proto,0);
        ZEROFILL10(hdr.http_proto_sep,0);

        ZEROFILL10(hdr.http_url,0); 
        ZEROFILL10(hdr.http_url,10);
        ZEROFILL10(hdr.http_url,20);
        ZEROFILL(hdr.http_url,30);
        ZEROFILL(hdr.http_url,31);

        ZEROFILL10(hdr.http_url_tag,0); 
        ZEROFILL10(hdr.http_url_tag,10);
        ZEROFILL10(hdr.http_url_tag,20);
        ZEROFILL(hdr.http_url_tag,30);
        ZEROFILL(hdr.http_url_tag,31);

        ZEROFILL10(hdr.http_url_sep,0);
        ZEROFILL10(hdr.http_version,0);

        meta.url = 0;

        transition parse_http_proto;
    }

    // PARSE HTTP PROTO STRING
    state parse_http_proto
    {
        packet.extract(hdr.http_proto.next);
        meta.proto_len = meta.proto_len + 1;
        char_t ch = packet.lookahead<char_t>();
        transition select(ch.ch)
        {
            0x20: parse_http_proto_sep;
            default: parse_http_proto;
        }
    }

    // PARSE SEPARATER BETWEEN PROTO URL
    state parse_http_proto_sep
    {
        packet.extract(hdr.http_proto_sep.next);
        meta.proto_sep_len = meta.proto_sep_len + 1;
        char_t ch = packet.lookahead<char_t>();
        transition select(ch.ch)
        {
            0x20: parse_http_proto_sep;
            default: parse_http_url;
        }
    }

    // PARSE URL STRING
    state parse_http_url
    {
        packet.extract(hdr.http_url.next);
        meta.ch = (bit<256>)(hdr.http_url.last.ch);
        meta.ch_url_len = 31 - meta.url_len;
        meta.url_len = meta.url_len + 1;
        transition select(meta.ch_url_len)
        {
            0: parse_url_shift_done;
            TRANS_PARSE_URL_SHIFT10(1);
            TRANS_PARSE_URL_SHIFT10(11);
            TRANS_PARSE_URL_SHIFT10(21);
            TRANS_PARSE_URL_SHIFT(31,0);
        }
    }

    PARSE_URL_SHIFT10(1)
    PARSE_URL_SHIFT10(11)
    PARSE_URL_SHIFT10(21)
    PARSE_URL_SHIFT(31,0)

    state parse_url_shift_done
    {
        meta.url = meta.url | meta.ch;
        meta.url_isvalid = 1;
        char_t ch = packet.lookahead<char_t>();
        transition select(ch.ch)
        {
            0x20: parse_http_url_sep; // SPACE
            0x23: parse_http_url_tag; // '#' 
            0x3f: parse_http_url_tag; // '?' 
            default: parse_http_url;
        }
    }

    // PARSE URL TAG STRING
    state parse_http_url_tag
    {
        packet.extract(hdr.http_url_tag.next);
        meta.url_tag_len = meta.url_tag_len + 1;
        char_t ch = packet.lookahead<char_t>();
        transition select(ch.ch)
        {
            0x20: parse_http_url_sep; // SPACE
            default: parse_http_url_tag;
        }
    }

    // PARSE SEPARATER BETWEEN URL VERSION
    state parse_http_url_sep
    {
        packet.extract(hdr.http_url_sep.next);
        meta.url_sep_len = meta.url_sep_len + 1;
        char_t ch = packet.lookahead<char_t>();
        transition select(ch.ch)
        {
            0x20: parse_http_url_sep;
            default: parse_http_version;
        }
    }

    // PARSE VERSION STRING
    state parse_http_version
    {
        packet.extract(hdr.http_version.next);
        char_t ch = packet.lookahead<char_t>();
        meta.version_len = meta.version_len + 1;
        transition select(ch.ch)
        {
            0x0d: accept; // CR
            0x0a: accept; // LF
            default: parse_http_version;
        }
    }

}






// I N G R E S S   P R O C E S S I N G -----------------------------------

control UrlIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) 
{

    // PACKET DROPPING
    action drop() 
    {
        mark_to_drop(standard_metadata);
    }

    // PACKET MULTICASTING
    action act_multicast()
    {
        standard_metadata.mcast_grp = 1;
    }

    // PACKET FORWARD PORT SETTING
    action act_port_fwd( bit<9> port )
    {
        standard_metadata.egress_spec = port;
    }

    // PACKET FORWARD PORT SETTING
    table tbl_port 
    {
        key = 
        { 
            // CHECK DISTINATION IP ADDR
            hdr.ipv4.dstAddr: exact;
        }
        actions =
        {
            act_port_fwd;
            NoAction;
        }
        default_action = NoAction();

        // 10.0.0.1 -> port(1)
        // 10.0.0.2 -> port(2)
        // 10.0.0.3 -> port(3)
        const entries =
        {
            (0x0a000001): act_port_fwd(1);
            (0x0a000002): act_port_fwd(2);
            (0x0a000003): act_port_fwd(3);
        }
    }

    // URL MATCHED TO DROP 
    action act_http_url_match()
    {
        mark_to_drop(standard_metadata);
    }

    // URL EXACT MATCHING
    table tbl_http_url_exact
    {
        key =
        {
            // URL MATCH KEY
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
            meta.url: exact;
        }
        actions =
        {
            act_http_url_match;
            NoAction;
        }
        default_action = NoAction();

        // URL MATCH DATA
#include "include/url_exact.p4"
    }

    // URL LPM MATCHING
    table tbl_http_url_lpm
    {
        key =
        {
            // URL MATCH KEY
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
            meta.url: ternary;
        }
        actions =
        {
            act_http_url_match;
            NoAction;
        }
        default_action = NoAction();

        // URL MATCH DATA
#include "include/url_lpm.p4"
    }


    apply 
    {
        if( hdr.arp.isValid() )
        {
            // IF ARP THEN MULTICASTING
            act_multicast();
        }
        else if( hdr.ipv4.isValid() )
        {
            // IP PACKET PORT SETTING BY DST IP ADDR
            tbl_port.apply();

            if( meta.url_isvalid == 1 )
            {
                // IF HTTP URL PACKET MATCH TABLE APPLY
                tbl_http_url_exact.apply();
                tbl_http_url_lpm.apply();
            }
        }
    }
}





// E G R E S S   P R O C E S S I N G --------------------------------------

control UrlEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) 
{
    action drop() 
    {
        mark_to_drop(standard_metadata);
    }

    apply 
    {
        // Prune multicast packet to ingress port to preventing loop
        if( standard_metadata.egress_port == standard_metadata.ingress_port )
        {
            drop();
        }
    }
}





// D E P A R S E R  -----------------------------------------------------

control UrlDeparser(
    packet_out packet,
    in headers hdr
) 
{
    apply 
    {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_opt);
        packet.emit(hdr.http_proto);
        packet.emit(hdr.http_proto_sep);
        packet.emit(hdr.http_url);
        packet.emit(hdr.http_url_tag);
        packet.emit(hdr.http_url_sep);
        packet.emit(hdr.http_version);
    }
}





// C H E C K S U M    V E R I F I C A T I O N  ---------------------------

control UrlVerifyChecksum(
    inout headers hdr,
    inout metadata meta
)
{   
    apply {}
}


// C H E C K S U M    C O M P U T A T I O N  -----------------------------

control UrlComputeChecksum(
    inout headers  hdr,
    inout metadata meta
)
{ 
    apply {}
}






// S W I T C H -----------------------------------------------------------

V1Switch(
    UrlParser(),
    UrlVerifyChecksum(),
    UrlIngress(),
    UrlEgress(),
    UrlComputeChecksum(),
    UrlDeparser()
) main;

