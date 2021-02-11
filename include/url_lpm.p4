const entries = {
	// http://10.0.0.2:80/include/
	(
		0x0a000002,80,
		0x2f696e636c7564652f0000000000000000000000000000000000000000000000
		&&&
		0xffffffffffffffffff0000000000000000000000000000000000000000000000
	):act_http_url_match();
	// https://10.0.0.2:445/include/
	(
		0x0a000002,445,
		0x2f696e636c7564652f0000000000000000000000000000000000000000000000
		&&&
		0xffffffffffffffffff0000000000000000000000000000000000000000000000
	):act_http_url_match();
	// http://10.0.0.2:80/set/
	(
		0x0a000002,80,
		0x2f7365742f000000000000000000000000000000000000000000000000000000
		&&&
		0xffffffffff000000000000000000000000000000000000000000000000000000
	):act_http_url_match();
	// https://10.0.0.2:445/set/
	(
		0x0a000002,445,
		0x2f7365742f000000000000000000000000000000000000000000000000000000
		&&&
		0xffffffffff000000000000000000000000000000000000000000000000000000
	):act_http_url_match();
	// http://10.0.0.2:8000/set/
	(
		0x0a000002,8000,
		0x2f7365742f000000000000000000000000000000000000000000000000000000
		&&&
		0xffffffffff000000000000000000000000000000000000000000000000000000
	):act_http_url_match();
}
