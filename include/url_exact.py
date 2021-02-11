#!/usr/bin/env python3

urls = [
	[ "0x0a000002","/index.html" ],
	[ "0x0a000003","/hello.html" ]
]

for ui in range(len(urls)):
	ipaddr,url = urls[ui]
	l = len(url)
	print( "// URI:%s" % (url) )
	print( "(%s," % (ipaddr),end="" )
	for i in range(l):
		print( "0x%x," % (ord(url[i])),end="")
	for i in range(32-l-1):
		print( "0,",end="" )
	print( "0):act_http_url_match();" )

