/* -*- P4_16 -*- */
//********************************************************************
//*    SOURCE: url.p4                                                *
//*   PURPOSE: URL Filterng by p4                                    *
//* FORMATTED: P4_16 v1model (16 SEP 2020 version)                   *
//*   WRITTEN: 2021/02/09 Matsushita "spicy" Keishin                 *
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
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
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
    char_t[10]   http_proto;     // GET            HTTP PROTOCOL
    char_t[10]   http_proto_sep; // ' '            HTTP PROTOCOL SPECE
    char_t[32]   http_url;       // /index.html    HTTP URL MAX LENGTH 32
    char_t[32]   http_url_tag;   // ?id=20         HTTP URL TAG ?,#
    char_t[10]   http_url_sep;   // ' '            HTTP URL SPECE
    char_t[10]   http_version;   // HTTP/1.1       HTTP VERSION
}

struct metadata 
{
    bit<16>     proto_len;
    bit<16>     proto_sep_len;
    bit<16>     url_len;
    bit<16>     url_tag_len;
    bit<16>     url_sep_len;
    bit<16>     version_len;
    bit<1>      url_isvalid;
}


#define zerofill(item,idx)  \
    item[idx].setValid();   \
    item[idx].ch = 0;       \
    item[idx].setInvalid()

#define zerofill10(a,idx)   \
	zerofill(a,idx);        \
	zerofill(a,idx+1);      \
	zerofill(a,idx+2);      \
	zerofill(a,idx+3);      \
	zerofill(a,idx+4);      \
	zerofill(a,idx+5);      \
	zerofill(a,idx+6);      \
	zerofill(a,idx+7);      \
	zerofill(a,idx+8);      \
	zerofill(a,idx+9)

#define zerofill30(a,idx)   \
    zerofill10(a,idx);      \
    zerofill10(a,idx+10);   \
    zerofill10(a,idx+20)

#define keydef(op,item,idx)  item[idx].ch: op

#define keydef10(op,item,idx) \
    keydef(op,item,idx);      \
    keydef(op,item,idx+1);    \
    keydef(op,item,idx+2);    \
    keydef(op,item,idx+3);    \
    keydef(op,item,idx+4);    \
    keydef(op,item,idx+5);    \
    keydef(op,item,idx+6);    \
    keydef(op,item,idx+7);    \
    keydef(op,item,idx+8);    \
    keydef(op,item,idx+9)

#define keydef30(op,item,idx) \
    keydef10(op,item,idx);    \
    keydef10(op,item,idx+10); \
    keydef10(op,item,idx+20)




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
        transition select(hdr.tcp.dstPort)
        {
	    // PARSE TARGET DST PORT
            80:  parse_http_init;
            445: parse_http_init;
            8000:  parse_http_init;
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
    	meta.url_isvalid   = 0;

	zerofill10(hdr.http_proto,0);
	zerofill10(hdr.http_proto_sep,0);

	zerofill30(hdr.http_url,0);
	zerofill(hdr.http_url,30);
	zerofill(hdr.http_url,31);

	zerofill30(hdr.http_url_tag,0);
	zerofill(hdr.http_url_tag,30);
	zerofill(hdr.http_url_tag,31);

	zerofill10(hdr.http_url_sep,0);
	zerofill10(hdr.http_version,0);

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
	meta.url_len = meta.url_len + 1;
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

    // URL MATCHING
    table tbl_http_url
    {
	key =
	{
	    // URL MATCH KEY
	    hdr.ipv4.dstAddr: exact;
	    keydef30(exact,hdr.http_url,0);
	    keydef(exact,hdr.http_url,30);
	    keydef(exact,hdr.http_url,31);
	}
	actions =
	{
            act_http_url_match;
	    NoAction;
	}
        default_action = NoAction();

	// URL MATCH DATA
	const entries = {
#include "include/url.p4"
	}
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
		tbl_http_url.apply();
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

