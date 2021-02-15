/* -*- P4_16 -*- */
//********************************************************************
//*    SOURCE: url.p4                                                *
//*   PURPOSE: URL Filterng by p4                                    *
//* FORMATTED: P4_16 v1model (16 SEP 2020 version)                   *
//*   WRITTEN: 2021/02/09 Matsushita "spicy" Keishin                 *
//*  REVISION: 0.012 2021/02/11                                      *
//********************************************************************

#include <core.p4>
#include <v1model.p4>

// CONST VALUES
const bit<16> TYPE_ARP  = 0x806;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP = 6;

#define URL_BYTES    256
#define URL_BYTES_1  255
#define URL_BITS	 (URL_BYTES*8)

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
    ethernet_t         ethernet;
    arp_t              arp;
    ipv4_t             ipv4;
    tcp_t              tcp;
    tcp_opt_t          tcp_opt;
    char_t[10]         http_proto;     // GET,POST      HTTP PROTOCOL
    char_t[10]         http_proto_sep; // ' '           HTTP PROTOCOL SPACE
    char_t[URL_BYTES]  http_url;       // /index.html   HTTP URL
    char_t[URL_BYTES]  http_url_tag;   // ?id=20        HTTP URL TAG ?,#
    char_t[10]         http_url_sep;   // ' '           HTTP URL SPACE
    char_t[10]         http_version;   // HTTP/1.1      HTTP VERSION
}

struct metadata 
{
    // HTTP INFO
    bit<16>         proto_len;
    bit<16>         proto_sep_len;
    bit<16>         url_tag_len;
    bit<16>         url_sep_len;
    bit<16>         version_len;
    bit<16>         url_len;
    bit<16>         ch_url_len;
    bit<URL_BITS>   url;
    bit<URL_BITS>   ch;
    bit<1>          url_isvalid;
}

#include "include/define.p4"





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

        // ZEROFILL10(hdr.http_proto,0);
        // ZEROFILL10(hdr.http_proto_sep,0);

        ZEROFILLMAX(hdr.http_url); 

        // ZEROFILLMAX(hdr.http_url_tag); 

        // ZEROFILL10(hdr.http_url_sep,0);
        // ZEROFILL10(hdr.http_version,0);

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
        meta.ch = (bit<URL_BITS>)(hdr.http_url.last.ch);
        meta.ch_url_len = URL_BYTES_1 - meta.url_len;
        meta.url_len = meta.url_len + 1;
        transition select(meta.ch_url_len)
        {
            0: parse_url_shift_done;
            TRANS_PARSE_URL_SHIFT_MAX();
        }
    }

    PARSE_URL_SHIFT_MAX()

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
        }

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
        }

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
                if( ! tbl_http_url_lpm.apply().hit )
                {
                    // LPM UNMATCH URL
                    tbl_http_url_exact.apply();
                }
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

