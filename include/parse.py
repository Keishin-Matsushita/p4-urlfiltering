#!/usr/bin/env python3

for i in range(32):
	print( "\t\thdr.http_url[%d].setValid();" % (i) )
	print( "\t\thdr.http_url[%d].ch = 0;" % (i) )
	print( "\t\thdr.http_url[%d].setInvalid();" % (i) )
