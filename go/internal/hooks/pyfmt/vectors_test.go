package pyfmt

// Code generated from Python 3 repr(); see TestReprStrings. DO NOT EDIT by hand.

var pyStrRepr = []struct{ in, want string }{
	{"", "''"},
	{"abc", "'abc'"},
	{"it's", "\"it's\""},
	{"say \"hi\"", "'say \"hi\"'"},
	{"both ' and \"", "'both \\' and \"'"},
	{"back\\slash", "'back\\\\slash'"},
	{"tab\tnl\nret\r", "'tab\\tnl\\nret\\r'"},
	{"\u0000\u001f\u007f", "'\\x00\\x1f\\x7f'"},
	{"\u00e9", "'\u00e9'"},
	{"\u65e5\u672c", "'\u65e5\u672c'"},
	{"\u00a0", "'\\xa0'"},
	{"\u200b", "'\\u200b'"},
	{"\U0001F600", "'\U0001F600'"},
	{"\ue000", "'\\ue000'"},
	{"\u2028", "'\\u2028'"},
	{"<script>alert('x')</script>", "\"<script>alert('x')</script>\""},
	{"a\u0301", "'a\u0301'"},
}

var pyFloatRepr = []struct {
	in   float64
	want string
}{
	{1.0, "1.0"},
	{1.5, "1.5"},
	{0.1, "0.1"},
	{1e+16, "1e+16"},
	{1000000000000000.0, "1000000000000000.0"},
	{1.2345678901234568e+17, "1.2345678901234568e+17"},
	{0.0001, "0.0001"},
	{1e-05, "1e-05"},
	{0.00012345, "0.00012345"},
	{-2.5, "-2.5"},
	{1e+300, "1e+300"},
	{5e-324, "5e-324"},
	{0.0, "0.0"},
	{negZero, "-0.0"},
	{100.0, "100.0"},
	{12345.678, "12345.678"},
	{-1e-07, "-1e-07"},
	{1e+16, "1e+16"},
}
