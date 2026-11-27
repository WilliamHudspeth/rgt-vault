package actions

// Deliberate deviations from Python, one entry per vector. See parity_test.go:
// each is asserted in both directions.

const (
	devHard             = "link-local/metadata, multicast, unspecified and reserved targets stay blocked even with AllowPrivateNetwork (Python only blocks them without --allow-private-network)"
	devCGNAT            = "CGNAT 100.64.0.0/10 and site-local fec0::/10 are blocked (Python ipaddress.is_private misses them)"
	devNumeric          = "ambiguous numeric IPv4 hosts (decimal/octal/hex/short forms) are refused outright"
	devPort0            = "port 0 is refused"
	devUserinfo         = "credentials/userinfo in the URL are refused (Python accepts and silently uses the part after @)"
	devIDN              = "non-ASCII (IDN) hosts must be supplied as punycode"
	devCtl              = "whitespace, control or non-ASCII characters anywhere in the URL are refused (Python strips or accepts them)"
	devLen              = "URLs longer than 2048 bytes are refused"
	devHdrType          = "only string, number and boolean header values are accepted (Python stringifies null/list/object with str())"
	devHdrCRLF          = "CR, LF and NUL in header values are refused (header injection)"
	devHdrName          = "header names must be RFC 7230 tokens"
	devHdrASCII         = "header values must be printable ASCII"
	devHdrAuth          = "Authorization is owned by the action; a caller-supplied one is refused (Python lets a lowercase \"authorization\" coexist with the injected header)"
	devHdrHop           = "hop-by-hop, framing and proxy headers are refused"
	devHdrSpoof         = "client-address spoofing headers (Forwarded, X-Forwarded-*, X-Real-IP) are refused"
	devHdrDup           = "header names differing only in case are refused as ambiguous"
	devHdrCap           = "header count/size caps (32 headers, 128-byte names, 4 KiB values, 16 KiB total)"
	devHdrNil           = "nil headers mean \"none\" (the action layer does params.get(\"headers\") or {}); Python rejects a bare None only because _validate_headers is never called with one"
	devBaseQuery        = "openai_chat base_url must not carry a query or fragment (Python builds a broken URL from it)"
	devBaseAllowPrivate = "openai_chat base_url honours AllowPrivateNetwork (Python always re-validated base_url with allow_private_network=False, so a private base_url could never work)"
)

type deviation struct {
	goVerdict string
	reason    string
}

var urlDeviations = map[string]deviation{
	"url-034-priv": {"reject", devHard},
	"url-035-priv": {"reject", devHard},
	"url-036-priv": {"reject", devHard},
	"url-037-priv": {"reject", devHard},
	"url-043-pub":  {"reject", devCGNAT},
	"url-044-pub":  {"reject", devCGNAT},
	"url-045-priv": {"reject", devHard},
	"url-046-priv": {"reject", devHard},
	"url-047-priv": {"reject", devHard},
	"url-054-priv": {"reject", devHard},
	"url-055-priv": {"reject", devHard},
	"url-058-pub":  {"reject", devCGNAT},
	"url-059-priv": {"reject", devHard},
	"url-062-priv": {"reject", devHard},
	"url-065-priv": {"reject", devHard},
	"url-072-priv": {"reject", devHard},
	"url-074-priv": {"reject", devNumeric},
	"url-075-priv": {"reject", devNumeric},
	"url-076-priv": {"reject", devNumeric},
	"url-077-priv": {"reject", devNumeric},
	"url-078-priv": {"reject", devNumeric},
	"url-079-priv": {"reject", devNumeric},
	"url-080-priv": {"reject", devNumeric},
	"url-081-priv": {"reject", devNumeric},
	"url-084-pub":  {"reject", devNumeric},
	"url-084-priv": {"reject", devNumeric},
	"url-085-pub":  {"reject", devNumeric},
	"url-085-priv": {"reject", devNumeric},
	"url-092-priv": {"reject", devHard},
	"url-093-pub":  {"reject", devCGNAT},
	"url-098-pub":  {"reject", devPort0},
	"url-098-priv": {"reject", devPort0},
	"url-111-pub":  {"reject", devUserinfo},
	"url-111-priv": {"reject", devUserinfo},
	"url-112-pub":  {"reject", devUserinfo},
	"url-112-priv": {"reject", devUserinfo},
	"url-113-pub":  {"reject", devUserinfo},
	"url-113-priv": {"reject", devUserinfo},
	"url-114-priv": {"reject", devUserinfo},
	"url-115-pub":  {"reject", devUserinfo},
	"url-115-priv": {"reject", devUserinfo},
	"url-116-priv": {"reject", devUserinfo},
	"url-117-pub":  {"reject", devUserinfo},
	"url-117-priv": {"reject", devUserinfo},
	"url-118-priv": {"reject", devUserinfo},
	"url-119-pub":  {"reject", devUserinfo},
	"url-119-priv": {"reject", devUserinfo},
	"url-123-priv": {"reject", devUserinfo},
	"url-124-pub":  {"reject", devUserinfo},
	"url-124-priv": {"reject", devUserinfo},
	"url-125-pub":  {"reject", devIDN},
	"url-125-priv": {"reject", devIDN},
	"url-130-priv": {"reject", devIDN},
	"url-141-pub":  {"reject", devCtl},
	"url-141-priv": {"reject", devCtl},
	"url-142-pub":  {"reject", devCtl},
	"url-142-priv": {"reject", devCtl},
	"url-143-pub":  {"reject", devCtl},
	"url-143-priv": {"reject", devCtl},
	"url-144-pub":  {"reject", devCtl},
	"url-144-priv": {"reject", devCtl},
	"url-145-pub":  {"reject", devCtl},
	"url-145-priv": {"reject", devCtl},
	"url-146-pub":  {"reject", devCtl},
	"url-146-priv": {"reject", devCtl},
	"url-148-pub":  {"reject", devCtl},
	"url-148-priv": {"reject", devCtl},
	"url-149-pub":  {"reject", devCtl},
	"url-149-priv": {"reject", devCtl},
	"url-153-pub":  {"reject", devLen},
	"url-153-priv": {"reject", devLen},
}

var headerDeviations = map[string]deviation{
	"null-value":          {"reject", devHdrType},
	"list-value":          {"reject", devHdrType},
	"obj-value":           {"reject", devHdrType},
	"crlf-value":          {"reject", devHdrCRLF},
	"lf-value":            {"reject", devHdrCRLF},
	"nul-value":           {"reject", devHdrCRLF},
	"crlf-name":           {"reject", devHdrName},
	"space-name":          {"reject", devHdrName},
	"colon-name":          {"reject", devHdrName},
	"empty-name":          {"reject", devHdrName},
	"unicode-name":        {"reject", devHdrName},
	"unicode-value":       {"reject", devHdrASCII},
	"ctl-value":           {"reject", devHdrASCII},
	"del-value":           {"reject", devHdrASCII},
	"authorization":       {"reject", devHdrAuth},
	"authorization-lower": {"reject", devHdrAuth},
	"proxy-authorization": {"reject", devHdrHop},
	"content-length":      {"reject", devHdrHop},
	"transfer-encoding":   {"reject", devHdrHop},
	"connection":          {"reject", devHdrHop},
	"upgrade":             {"reject", devHdrHop},
	"te":                  {"reject", devHdrHop},
	"expect":              {"reject", devHdrHop},
	"x-forwarded-for":     {"reject", devHdrSpoof},
	"forwarded":           {"reject", devHdrSpoof},
	"x-real-ip":           {"reject", devHdrSpoof},
	"dup-case":            {"reject", devHdrDup},
	"long-value":          {"reject", devHdrCap},
	"long-name":           {"reject", devHdrCap},
	"many":                {"reject", devHdrCap},
	"not-object-null":     {"accept", devHdrNil},
}

var actionDeviations = map[string]deviation{
	"oa-base-query-pub":     {"reject", devBaseQuery},
	"oa-base-query-priv":    {"reject", devBaseQuery},
	"oa-base-frag-pub":      {"reject", devBaseQuery},
	"oa-base-frag-priv":     {"reject", devBaseQuery},
	"oa-base-loopback-priv": {"accept", devBaseAllowPrivate},
	"oa-base-internal-priv": {"accept", devBaseAllowPrivate},
	"oa-base-userinfo-pub":  {"reject", devUserinfo},
	"oa-base-userinfo-priv": {"reject", devUserinfo},
	"get-crlf-header-pub":   {"reject", devHdrCRLF},
	"get-crlf-header-priv":  {"reject", devHdrCRLF},
	"get-auth-header-pub":   {"reject", devHdrAuth},
	"get-auth-header-priv":  {"reject", devHdrAuth},
	"get-metadata-priv":     {"reject", devHard},
}
