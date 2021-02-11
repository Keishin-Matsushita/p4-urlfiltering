#!/usr/bin/env python3

urls = [
	[ "0x0a000002","/include/" ]
]

for ui in range(len(urls)):
	ipaddr,url = urls[ui]
	l = len(url)
	print( "// URI:%s" % (url) )
	print( "(" )
	print( "\t%s," % (ipaddr) )
	s = "0x"
	lpm = "0x"
	for i in range(l):
		s = s + ("%02x" % (ord(url[i])))
		lpm = lpm + "ff"
	for i in range(32-l):
		s = s + "00"
		lpm = lpm + "00"
	print( "\t%s" % (s) )
	print( "\t&&&" )
	print( "\t%s" % (lpm) )
	print( "):act_http_url_match();" )

