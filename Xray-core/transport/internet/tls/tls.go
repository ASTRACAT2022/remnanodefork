package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
)

type Interface interface {
	net.Conn
	HandshakeContext(ctx context.Context) error
	VerifyHostname(host string) error
	HandshakeContextServerName(ctx context.Context) string
	NegotiatedProtocol() string
}

var (
	_ buf.Writer = (*Conn)(nil)
	_ Interface  = (*Conn)(nil)
)

type Conn struct {
	*tls.Conn
}

const tlsCloseTimeout = 250 * time.Millisecond

func (c *Conn) Close() error {
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *Conn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

func (c *Conn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn}
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &Conn{Conn: tlsConn}
}

type UConn struct {
	*utls.UConn
}

var _ Interface = (*UConn)(nil)

func (c *UConn) Close() error {
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *UConn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

// WebsocketHandshakeContext basically calls UConn.Handshake inside it but it will try
// to build outer ALPN to `http/1.1` or `h2 http/1.1` (if manually specified for camouflage)
func (c *UConn) WebsocketHandshakeContext(ctx context.Context) error {
	config := *utils.AccessField[*utls.Config](c, "config")
	ALPN := slices.Clone(config.NextProtos)
	// set other kinds of ALPN to http/1.1
	if !slices.Equal(ALPN, []string{"h2", "http/1.1"}) {
		ALPN = []string{"http/1.1"}
	}
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Do not modify outer ALPN if ECH is used
	// Outer ALPN will be h2,http/1.1, and real http/1.1 in config will be hidden in ECH
	if config.EncryptedClientHelloConfigList != nil {
		config.NextProtos = []string{"http/1.1"}
		return c.HandshakeContext(ctx)
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = ALPN
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: ALPN})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.HandshakeContext(ctx)
}

func (c *UConn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	utlsConn := utls.UClient(c, copyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func GeneraticUClient(c net.Conn, config *tls.Config) *utls.UConn {
	return utls.UClient(c, copyConfig(config), utls.HelloChrome_Auto)
}

func copyConfig(c *tls.Config) *utls.Config {
	config := &utls.Config{
		Rand:                           c.Rand,
		RootCAs:                        c.RootCAs,
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		KeyLogWriter:                   c.KeyLogWriter,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
		NextProtos:                     c.NextProtos,
	}
	return config
}

type FingerprintProfile struct {
	Name        string
	HelloID     *utls.ClientHelloID
	Description string
	Versioned   bool
	Selected    string
}

var (
	chromeAutoFingerprint  = utls.HelloChrome_Auto
	firefoxAutoFingerprint = utls.HelloFirefox_Auto
	safariAutoFingerprint  = utls.HelloSafari_Auto

	randomFingerprint           utls.ClientHelloID
	randomizedFingerprint       utls.ClientHelloID
	randomizedNoALPNFingerprint utls.ClientHelloID
)

func selectRandomFingerprint() utls.ClientHelloID {
	if len(randomFingerprintPool) == 0 {
		return utls.HelloChrome_Auto
	}
	bigInt, err := rand.Int(rand.Reader, big.NewInt(int64(len(randomFingerprintPool))))
	if err != nil {
		return *randomFingerprintPool[0].HelloID
	}
	return *randomFingerprintPool[int(bigInt.Int64())].HelloID
}

func newRandomizedFingerprint(base utls.ClientHelloID) utls.ClientHelloID {
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	fingerprint := base
	fingerprint.Seed, _ = utls.NewPRNGSeed()
	fingerprint.Weights = &weights
	return fingerprint
}

func init() {
	randomFingerprint = selectRandomFingerprint()
	randomizedFingerprint = newRandomizedFingerprint(utls.HelloRandomizedALPN)
	randomizedNoALPNFingerprint = newRandomizedFingerprint(utls.HelloRandomizedNoALPN)
	fingerprintRegistry["random"] = FingerprintProfile{Name: "random", HelloID: &randomFingerprint, Description: "One browser profile selected at process startup", Selected: randomFingerprint.Str()}
	errors.LogDebug(context.Background(), "resolved TLS fingerprint: requested=random selected=", randomFingerprint.Str())
}

func GetFingerprint(name string) (fingerprint *utls.ClientHelloID) {
	if profile, ok := ResolveFingerprint(name); ok {
		if profile.Selected != "" && profile.Selected != profile.Name {
			errors.LogDebug(context.Background(), "resolved TLS fingerprint: requested=", profile.Name, " selected=", profile.Selected)
		}
		return profile.HelloID
	}
	return
}

func ResolveFingerprint(name string) (FingerprintProfile, bool) {
	normalized := NormalizeFingerprint(name)
	if profile, ok := fingerprintRegistry[normalized]; ok {
		return profile, true
	}
	if profile, ok := resolveCompatibleBrowserFingerprint(normalized); ok {
		return profile, true
	}
	return FingerprintProfile{}, false
}

func NormalizeFingerprint(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "chrome"
	}
	normalized = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(normalized)
	for strings.Contains(normalized, "__") {
		normalized = strings.ReplaceAll(normalized, "__", "_")
	}
	normalized = strings.Trim(normalized, "_")
	normalized = strings.TrimPrefix(normalized, "utls_")
	if strings.HasPrefix(normalized, "hello_") {
		normalized = "hello" + strings.TrimPrefix(normalized, "hello_")
	}
	normalized = normalizeBrowserVersionName(normalized)
	if alias, ok := fingerprintAliases[normalized]; ok {
		return alias
	}
	return normalized
}

func normalizeBrowserVersionName(name string) string {
	for _, browser := range []string{"chrome", "firefox", "safari", "edge", "yandex", "android", "hellochrome", "hellofirefox", "helloios", "helloedge", "hellosafari"} {
		suffix := strings.TrimPrefix(name, browser)
		if suffix == name || suffix == "" || strings.HasPrefix(suffix, "_") {
			continue
		}
		if _, err := strconv.Atoi(suffix); err == nil {
			return browser + "_" + suffix
		}
	}
	return name
}

func resolveCompatibleBrowserFingerprint(name string) (FingerprintProfile, bool) {
	switch {
	case strings.HasPrefix(name, "chrome_"):
		return compatibleChromeFingerprint(name)
	case strings.HasPrefix(name, "hellochrome_"):
		return compatibleHelloChromeFingerprint(name)
	case strings.HasPrefix(name, "firefox_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloFirefox_120, Description: "Closest Firefox profile available in this uTLS build", Versioned: true, Selected: "firefox_120"}, true
	case strings.HasPrefix(name, "hellofirefox_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloFirefox_120, Description: "Closest Firefox profile available in this uTLS build", Versioned: true, Selected: "hellofirefox_120"}, true
	case strings.HasPrefix(name, "safari_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloSafari_16_0, Description: "Closest Safari profile available in this uTLS build", Versioned: true, Selected: "safari_16_0"}, true
	case strings.HasPrefix(name, "hellosafari_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloSafari_16_0, Description: "Closest Safari profile available in this uTLS build", Versioned: true, Selected: "hellosafari_16_0"}, true
	case strings.HasPrefix(name, "edge_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloEdge_85, Description: "Closest Edge profile available in this uTLS build", Versioned: true, Selected: "edge_85"}, true
	case strings.HasPrefix(name, "helloedge_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloEdge_85, Description: "Closest Edge profile available in this uTLS build", Versioned: true, Selected: "helloedge_85"}, true
	case strings.HasPrefix(name, "yandex_"):
		return FingerprintProfile{Name: name, HelloID: &chromeAutoFingerprint, Description: "Yandex Browser uses the closest supported Chromium profile", Versioned: true, Selected: "chrome_133"}, true
	case strings.HasPrefix(name, "android_"):
		return FingerprintProfile{Name: name, HelloID: &utls.HelloAndroid_11_OkHttp, Description: "Closest Android profile available in this uTLS build", Versioned: true, Selected: "android"}, true
	default:
		return FingerprintProfile{}, false
	}
}

func compatibleHelloChromeFingerprint(name string) (FingerprintProfile, bool) {
	version, ok := versionSuffix(name, "hellochrome_")
	if !ok {
		return FingerprintProfile{}, false
	}
	selected := "hellochrome_133"
	helloID := &utls.HelloChrome_133
	if version <= 126 {
		selected = "hellochrome_120"
		helloID = &utls.HelloChrome_120
	} else if version <= 132 {
		selected = "hellochrome_131"
		helloID = &utls.HelloChrome_131
	}
	return FingerprintProfile{Name: name, HelloID: helloID, Description: "Closest legacy Chrome profile available in this uTLS build", Versioned: true, Selected: selected}, true
}

func compatibleChromeFingerprint(name string) (FingerprintProfile, bool) {
	version, ok := versionSuffix(name, "chrome_")
	if !ok {
		return FingerprintProfile{}, false
	}
	selected := "chrome_133"
	helloID := &utls.HelloChrome_133
	if version <= 126 {
		selected = "chrome_120"
		helloID = &utls.HelloChrome_120
	} else if version <= 132 {
		selected = "chrome_131"
		helloID = &utls.HelloChrome_131
	}
	return FingerprintProfile{Name: name, HelloID: helloID, Description: "Closest Chrome profile available in this uTLS build", Versioned: true, Selected: selected}, true
}

func versionSuffix(name string, prefix string) (int, bool) {
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == name || suffix == "" {
		return 0, false
	}
	if idx := strings.IndexByte(suffix, '_'); idx >= 0 {
		suffix = suffix[:idx]
	}
	version, err := strconv.Atoi(suffix)
	return version, err == nil
}

var randomFingerprintPool = []FingerprintProfile{
	{Name: "chrome_120", HelloID: &utls.HelloChrome_120, Description: "Chrome 120", Versioned: true},
	{Name: "chrome_131", HelloID: &utls.HelloChrome_131, Description: "Chrome 131", Versioned: true},
	{Name: "chrome_133", HelloID: &utls.HelloChrome_133, Description: "Chrome 133", Versioned: true},
	{Name: "firefox_120", HelloID: &utls.HelloFirefox_120, Description: "Firefox 120", Versioned: true},
	{Name: "ios_13", HelloID: &utls.HelloIOS_13, Description: "iOS 13", Versioned: true},
	{Name: "ios_14", HelloID: &utls.HelloIOS_14, Description: "iOS 14", Versioned: true},
	{Name: "edge_85", HelloID: &utls.HelloEdge_85, Description: "Edge 85", Versioned: true},
	{Name: "safari_16_0", HelloID: &utls.HelloSafari_16_0, Description: "Safari 16.0", Versioned: true},
	{Name: "360_7_5", HelloID: &utls.Hello360_7_5, Description: "360 Browser 7.5", Versioned: true},
	{Name: "qq_11_1", HelloID: &utls.HelloQQ_11_1, Description: "QQ Browser 11.1", Versioned: true},
}

var fingerprintRegistry = map[string]FingerprintProfile{
	// Recommended preset options in GUI clients.
	"chrome":       {Name: "chrome", HelloID: &chromeAutoFingerprint, Description: "Latest stable Chrome profile available in uTLS v1.8.2", Selected: "chrome_133"},
	"chrome_auto":  {Name: "chrome_auto", HelloID: &chromeAutoFingerprint, Description: "Process-stable Chrome auto profile", Selected: "chrome_133"},
	"chrome_120":   {Name: "chrome_120", HelloID: &utls.HelloChrome_120, Description: "Chrome 120", Versioned: true},
	"chrome_124":   {Name: "chrome_124", HelloID: &utls.HelloChrome_120, Description: "Closest uTLS v1.8.2 profile for Chrome 124", Versioned: true, Selected: "chrome_120"},
	"chrome_126":   {Name: "chrome_126", HelloID: &utls.HelloChrome_120, Description: "Closest uTLS v1.8.2 profile for Chrome 126", Versioned: true, Selected: "chrome_120"},
	"chrome_128":   {Name: "chrome_128", HelloID: &utls.HelloChrome_131, Description: "Closest uTLS v1.8.2 profile for Chrome 128", Versioned: true, Selected: "chrome_131"},
	"chrome_131":   {Name: "chrome_131", HelloID: &utls.HelloChrome_131, Description: "Chrome 131", Versioned: true},
	"chrome_133":   {Name: "chrome_133", HelloID: &utls.HelloChrome_133, Description: "Chrome 133", Versioned: true},
	"firefox":      {Name: "firefox", HelloID: &firefoxAutoFingerprint, Description: "Latest stable Firefox profile available in uTLS v1.8.2", Selected: "firefox_120"},
	"firefox_auto": {Name: "firefox_auto", HelloID: &firefoxAutoFingerprint, Description: "Process-stable Firefox auto profile", Selected: "firefox_120"},
	"firefox_120":  {Name: "firefox_120", HelloID: &utls.HelloFirefox_120, Description: "Firefox 120", Versioned: true},
	"firefox_125":  {Name: "firefox_125", HelloID: &utls.HelloFirefox_120, Description: "Closest uTLS v1.8.2 profile for Firefox 125", Versioned: true, Selected: "firefox_120"},
	"safari":       {Name: "safari", HelloID: &safariAutoFingerprint, Description: "Latest stable Safari profile available in uTLS v1.8.2", Selected: "safari_16_0"},
	"safari_auto":  {Name: "safari_auto", HelloID: &safariAutoFingerprint, Description: "Process-stable Safari auto profile", Selected: "safari_16_0"},
	"safari_16_0":  {Name: "safari_16_0", HelloID: &utls.HelloSafari_16_0, Description: "Safari 16.0", Versioned: true},
	"ios":          {Name: "ios", HelloID: &utls.HelloIOS_Auto, Description: "Latest iOS profile available in uTLS v1.8.2", Selected: "ios_14"},
	"android":      {Name: "android", HelloID: &utls.HelloAndroid_11_OkHttp, Description: "Android 11 OkHttp profile"},
	"edge":         {Name: "edge", HelloID: &utls.HelloEdge_Auto, Description: "Latest compatible Edge profile available in uTLS v1.8.2", Selected: "edge_85"},
	"yandex":       {Name: "yandex", HelloID: &chromeAutoFingerprint, Description: "Yandex Browser uses the closest supported Chromium profile", Selected: "chrome_133"},
	"yandex_auto":  {Name: "yandex_auto", HelloID: &chromeAutoFingerprint, Description: "Process-stable Yandex/Chromium-compatible profile", Selected: "chrome_133"},
	"360":          {Name: "360", HelloID: &utls.Hello360_Auto, Description: "360 Browser profile", Selected: "360_7_5"},
	"qq":           {Name: "qq", HelloID: &utls.HelloQQ_Auto, Description: "QQ Browser profile", Selected: "qq_11_1"},

	// Process-stable randomized choices.
	"random":           {Name: "random", HelloID: &randomFingerprint, Description: "One browser profile selected at process startup", Selected: randomFingerprint.Str()},
	"randomized":       {Name: "randomized", HelloID: &randomizedFingerprint, Description: "One randomized ALPN profile seeded at process startup"},
	"randomizednoalpn": {Name: "randomizednoalpn", HelloID: &randomizedNoALPNFingerprint, Description: "One randomized no-ALPN profile seeded at process startup"},
	"unsafe":           {Name: "unsafe", Description: "Use standard Go TLS for regular TLS; invalid for REALITY"},

	// Legacy uTLS names kept for existing configs.
	"hellogolang":             {Name: "hellogolang", HelloID: &utls.HelloGolang, Description: "Go TLS ClientHello"},
	"hellorandomized":         {Name: "hellorandomized", HelloID: &utls.HelloRandomized, Description: "Legacy uTLS randomized profile"},
	"hellorandomizedalpn":     {Name: "hellorandomizedalpn", HelloID: &utls.HelloRandomizedALPN, Description: "Legacy uTLS randomized ALPN profile"},
	"hellorandomizednoalpn":   {Name: "hellorandomizednoalpn", HelloID: &utls.HelloRandomizedNoALPN, Description: "Legacy uTLS randomized no-ALPN profile"},
	"hellofirefox_auto":       {Name: "hellofirefox_auto", HelloID: &firefoxAutoFingerprint, Description: "Legacy Firefox auto alias", Selected: "firefox_120"},
	"hellofirefox_55":         {Name: "hellofirefox_55", HelloID: &utls.HelloFirefox_55, Description: "Firefox 55", Versioned: true},
	"hellofirefox_56":         {Name: "hellofirefox_56", HelloID: &utls.HelloFirefox_56, Description: "Firefox 56", Versioned: true},
	"hellofirefox_63":         {Name: "hellofirefox_63", HelloID: &utls.HelloFirefox_63, Description: "Firefox 63", Versioned: true},
	"hellofirefox_65":         {Name: "hellofirefox_65", HelloID: &utls.HelloFirefox_65, Description: "Firefox 65", Versioned: true},
	"hellofirefox_99":         {Name: "hellofirefox_99", HelloID: &utls.HelloFirefox_99, Description: "Firefox 99", Versioned: true},
	"hellofirefox_102":        {Name: "hellofirefox_102", HelloID: &utls.HelloFirefox_102, Description: "Firefox 102", Versioned: true},
	"hellofirefox_105":        {Name: "hellofirefox_105", HelloID: &utls.HelloFirefox_105, Description: "Firefox 105", Versioned: true},
	"hellofirefox_120":        {Name: "hellofirefox_120", HelloID: &utls.HelloFirefox_120, Description: "Firefox 120", Versioned: true},
	"hellochrome_auto":        {Name: "hellochrome_auto", HelloID: &chromeAutoFingerprint, Description: "Legacy Chrome auto alias", Selected: "chrome_133"},
	"hellochrome_58":          {Name: "hellochrome_58", HelloID: &utls.HelloChrome_58, Description: "Chrome 58", Versioned: true},
	"hellochrome_62":          {Name: "hellochrome_62", HelloID: &utls.HelloChrome_62, Description: "Chrome 62", Versioned: true},
	"hellochrome_70":          {Name: "hellochrome_70", HelloID: &utls.HelloChrome_70, Description: "Chrome 70", Versioned: true},
	"hellochrome_72":          {Name: "hellochrome_72", HelloID: &utls.HelloChrome_72, Description: "Chrome 72", Versioned: true},
	"hellochrome_83":          {Name: "hellochrome_83", HelloID: &utls.HelloChrome_83, Description: "Chrome 83", Versioned: true},
	"hellochrome_87":          {Name: "hellochrome_87", HelloID: &utls.HelloChrome_87, Description: "Chrome 87", Versioned: true},
	"hellochrome_96":          {Name: "hellochrome_96", HelloID: &utls.HelloChrome_96, Description: "Chrome 96", Versioned: true},
	"hellochrome_100":         {Name: "hellochrome_100", HelloID: &utls.HelloChrome_100, Description: "Chrome 100", Versioned: true},
	"hellochrome_102":         {Name: "hellochrome_102", HelloID: &utls.HelloChrome_102, Description: "Chrome 102", Versioned: true},
	"hellochrome_106_shuffle": {Name: "hellochrome_106_shuffle", HelloID: &utls.HelloChrome_106_Shuffle, Description: "Chrome 106 with shuffled extensions", Versioned: true},
	"hellochrome_120":         {Name: "hellochrome_120", HelloID: &utls.HelloChrome_120, Description: "Chrome 120", Versioned: true},
	"hellochrome_131":         {Name: "hellochrome_131", HelloID: &utls.HelloChrome_131, Description: "Chrome 131", Versioned: true},
	"hellochrome_133":         {Name: "hellochrome_133", HelloID: &utls.HelloChrome_133, Description: "Chrome 133", Versioned: true},
	"helloios_auto":           {Name: "helloios_auto", HelloID: &utls.HelloIOS_Auto, Description: "Legacy iOS auto alias", Selected: "ios_14"},
	"helloios_11_1":           {Name: "helloios_11_1", HelloID: &utls.HelloIOS_11_1, Description: "iOS 11.1", Versioned: true},
	"helloios_12_1":           {Name: "helloios_12_1", HelloID: &utls.HelloIOS_12_1, Description: "iOS 12.1", Versioned: true},
	"helloios_13":             {Name: "helloios_13", HelloID: &utls.HelloIOS_13, Description: "iOS 13", Versioned: true},
	"helloios_14":             {Name: "helloios_14", HelloID: &utls.HelloIOS_14, Description: "iOS 14", Versioned: true},
	"helloandroid_11_okhttp":  {Name: "helloandroid_11_okhttp", HelloID: &utls.HelloAndroid_11_OkHttp, Description: "Android 11 OkHttp", Versioned: true},
	"helloedge_85":            {Name: "helloedge_85", HelloID: &utls.HelloEdge_85, Description: "Edge 85", Versioned: true},
	"helloedge_106":           {Name: "helloedge_106", HelloID: &utls.HelloEdge_106, Description: "Edge 106", Versioned: true},
	"helloedge_auto":          {Name: "helloedge_auto", HelloID: &utls.HelloEdge_Auto, Description: "Legacy Edge auto alias", Selected: "edge_85"},
	"helloyandex_auto":        {Name: "helloyandex_auto", HelloID: &chromeAutoFingerprint, Description: "Legacy Yandex auto alias", Selected: "chrome_133"},
	"hellosafari_16_0":        {Name: "hellosafari_16_0", HelloID: &utls.HelloSafari_16_0, Description: "Safari 16.0", Versioned: true},
	"hellosafari_auto":        {Name: "hellosafari_auto", HelloID: &safariAutoFingerprint, Description: "Legacy Safari auto alias", Selected: "safari_16_0"},
	"hello360_auto":           {Name: "hello360_auto", HelloID: &utls.Hello360_Auto, Description: "Legacy 360 Browser auto alias", Selected: "360_7_5"},
	"hello360_7_5":            {Name: "hello360_7_5", HelloID: &utls.Hello360_7_5, Description: "360 Browser 7.5", Versioned: true},
	"hello360_11_0":           {Name: "hello360_11_0", HelloID: &utls.Hello360_11_0, Description: "360 Browser 11.0", Versioned: true},
	"helloqq_auto":            {Name: "helloqq_auto", HelloID: &utls.HelloQQ_Auto, Description: "Legacy QQ Browser auto alias", Selected: "qq_11_1"},
	"helloqq_11_1":            {Name: "helloqq_11_1", HelloID: &utls.HelloQQ_11_1, Description: "QQ Browser 11.1", Versioned: true},

	// Chrome betas retained for compatibility with explicit legacy configs.
	"hellochrome_100_psk":              {Name: "hellochrome_100_psk", HelloID: &utls.HelloChrome_100_PSK, Description: "Chrome 100 PSK beta"},
	"hellochrome_112_psk_shuf":         {Name: "hellochrome_112_psk_shuf", HelloID: &utls.HelloChrome_112_PSK_Shuf, Description: "Chrome 112 PSK shuffled beta"},
	"hellochrome_114_padding_psk_shuf": {Name: "hellochrome_114_padding_psk_shuf", HelloID: &utls.HelloChrome_114_Padding_PSK_Shuf, Description: "Chrome 114 padding PSK shuffled beta"},
	"hellochrome_115_pq":               {Name: "hellochrome_115_pq", HelloID: &utls.HelloChrome_115_PQ, Description: "Chrome 115 PQ beta"},
	"hellochrome_115_pq_psk":           {Name: "hellochrome_115_pq_psk", HelloID: &utls.HelloChrome_115_PQ_PSK, Description: "Chrome 115 PQ PSK beta"},
	"hellochrome_120_pq":               {Name: "hellochrome_120_pq", HelloID: &utls.HelloChrome_120_PQ, Description: "Chrome 120 PQ beta"},
}

var fingerprintAliases = map[string]string{
	"brave":           "chrome",
	"brave_browser":   "chrome",
	"chromium":        "chrome",
	"google_chrome":   "chrome",
	"opera":           "chrome",
	"opera_browser":   "chrome",
	"vivaldi":         "chrome",
	"vivaldi_browser": "chrome",
	"ya_browser":      "yandex",
	"yabrowser":       "yandex",
	"yandex_browser":  "yandex",
	"yandexbrowser":   "yandex",
	"qqbrowser":       "qq",
	"qq_browser":      "qq",
	"360browser":      "360",
	"360_browser":     "360",
	"android_11":      "android",
}
