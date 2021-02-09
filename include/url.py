#!/usr/bin/env python3

urls = [
	[ "0x0a000002","GET / HTTP/1.1" ],
	[ "0x0a000003","GET /index.html HTTP/1.1" ],
	[ "0x0a000002","GET /hello.html HTTP/1.1" ]
]

for ui in range(len(urls)):
	ipaddr,url = urls[ui]
	url = url + chr(0x0d) + chr(0x0a)
	l = len(url)
	print( "(%s," % (ipaddr),end="" )
	for i in range(l):
		print( "0x%x," % (ord(url[i])),end="")
	for i in range(32-l-1):
		print( "0,",end="" )
	print( "0):act_http_url_match();" )

