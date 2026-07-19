package tls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestLegacyChromeFingerprint(t *testing.T) {
	fingerprint := GetFingerprint("chrome")
	if fingerprint == nil {
		t.Fatal("GetFingerprint(\"chrome\") returned nil")
	}
	if *fingerprint != utls.HelloChrome_Auto {
		t.Fatalf("GetFingerprint(\"chrome\") = %v, want %v", fingerprint.Str(), utls.HelloChrome_Auto.Str())
	}
}

func TestVersionedFingerprintAliases(t *testing.T) {
	tests := []struct {
		name     string
		want     utls.ClientHelloID
		selected string
	}{
		{name: "chrome_auto", want: utls.HelloChrome_Auto, selected: "chrome_133"},
		{name: "chrome_120", want: utls.HelloChrome_120},
		{name: "chrome_124", want: utls.HelloChrome_120, selected: "chrome_120"},
		{name: "chrome_126", want: utls.HelloChrome_120, selected: "chrome_120"},
		{name: "chrome_128", want: utls.HelloChrome_131, selected: "chrome_131"},
		{name: "firefox_auto", want: utls.HelloFirefox_Auto, selected: "firefox_120"},
		{name: "firefox_120", want: utls.HelloFirefox_120},
		{name: "firefox_125", want: utls.HelloFirefox_120, selected: "firefox_120"},
		{name: "safari_auto", want: utls.HelloSafari_Auto, selected: "safari_16_0"},
	}

	for _, test := range tests {
		fingerprint := GetFingerprint(test.name)
		if fingerprint == nil {
			t.Fatalf("GetFingerprint(%q) returned nil", test.name)
		}
		if *fingerprint != test.want {
			t.Fatalf("GetFingerprint(%q) = %v, want %v", test.name, fingerprint.Str(), test.want.Str())
		}
		profile, ok := ResolveFingerprint(test.name)
		if !ok {
			t.Fatalf("ResolveFingerprint(%q) returned false", test.name)
		}
		if profile.Selected != test.selected {
			t.Fatalf("ResolveFingerprint(%q).Selected = %q, want %q", test.name, profile.Selected, test.selected)
		}
	}
}

func TestYandexFingerprintAliasesChromeAuto(t *testing.T) {
	for _, name := range []string{"yandex", "yandex_auto", "helloyandex_auto", "Yandex-Browser", "YaBrowser"} {
		fingerprint := GetFingerprint(name)
		if fingerprint == nil {
			t.Fatalf("GetFingerprint(%q) returned nil", name)
		}
		if *fingerprint != utls.HelloChrome_Auto {
			t.Fatalf("GetFingerprint(%q) = %v, want %v", name, fingerprint.Str(), utls.HelloChrome_Auto.Str())
		}
	}
}

func TestFingerprintNormalizationForVanillaClients(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
		want       utls.ClientHelloID
		selected   string
	}{
		{name: "", normalized: "chrome", want: utls.HelloChrome_Auto, selected: "chrome_133"},
		{name: "Chrome", normalized: "chrome", want: utls.HelloChrome_Auto, selected: "chrome_133"},
		{name: "chrome-133", normalized: "chrome_133", want: utls.HelloChrome_133},
		{name: "HelloChrome133", normalized: "hellochrome_133", want: utls.HelloChrome_133},
		{name: "hello-chrome-133", normalized: "hellochrome_133", want: utls.HelloChrome_133},
		{name: "brave", normalized: "chrome", want: utls.HelloChrome_Auto, selected: "chrome_133"},
		{name: "google chrome", normalized: "chrome", want: utls.HelloChrome_Auto, selected: "chrome_133"},
	}

	for _, test := range tests {
		if normalized := NormalizeFingerprint(test.name); normalized != test.normalized {
			t.Fatalf("NormalizeFingerprint(%q) = %q, want %q", test.name, normalized, test.normalized)
		}
		fingerprint := GetFingerprint(test.name)
		if fingerprint == nil {
			t.Fatalf("GetFingerprint(%q) returned nil", test.name)
		}
		if *fingerprint != test.want {
			t.Fatalf("GetFingerprint(%q) = %v, want %v", test.name, fingerprint.Str(), test.want.Str())
		}
		profile, ok := ResolveFingerprint(test.name)
		if !ok {
			t.Fatalf("ResolveFingerprint(%q) returned false", test.name)
		}
		if profile.Selected != test.selected {
			t.Fatalf("ResolveFingerprint(%q).Selected = %q, want %q", test.name, profile.Selected, test.selected)
		}
	}
}

func TestCompatibleFutureBrowserVersionFallbacks(t *testing.T) {
	tests := []struct {
		name     string
		want     utls.ClientHelloID
		selected string
	}{
		{name: "chrome_134", want: utls.HelloChrome_133, selected: "chrome_133"},
		{name: "chrome999", want: utls.HelloChrome_133, selected: "chrome_133"},
		{name: "HelloChrome140", want: utls.HelloChrome_133, selected: "hellochrome_133"},
		{name: "firefox_130", want: utls.HelloFirefox_120, selected: "firefox_120"},
		{name: "HelloFirefox130", want: utls.HelloFirefox_120, selected: "hellofirefox_120"},
		{name: "safari_17_0", want: utls.HelloSafari_16_0, selected: "safari_16_0"},
		{name: "HelloSafari170", want: utls.HelloSafari_16_0, selected: "hellosafari_16_0"},
		{name: "edge_130", want: utls.HelloEdge_85, selected: "edge_85"},
		{name: "HelloEdge130", want: utls.HelloEdge_85, selected: "helloedge_85"},
		{name: "android_14", want: utls.HelloAndroid_11_OkHttp, selected: "android"},
	}

	for _, test := range tests {
		fingerprint := GetFingerprint(test.name)
		if fingerprint == nil {
			t.Fatalf("GetFingerprint(%q) returned nil", test.name)
		}
		if *fingerprint != test.want {
			t.Fatalf("GetFingerprint(%q) = %v, want %v", test.name, fingerprint.Str(), test.want.Str())
		}
		profile, ok := ResolveFingerprint(test.name)
		if !ok {
			t.Fatalf("ResolveFingerprint(%q) returned false", test.name)
		}
		if profile.Selected != test.selected {
			t.Fatalf("ResolveFingerprint(%q).Selected = %q, want %q", test.name, profile.Selected, test.selected)
		}
	}
}

func TestAutoFingerprintIsProcessStable(t *testing.T) {
	first := GetFingerprint("chrome_auto")
	second := GetFingerprint("chrome_auto")
	if first == nil || second == nil {
		t.Fatal("chrome_auto returned nil")
	}
	if first != second {
		t.Fatal("chrome_auto returned different ClientHelloID pointers in one process")
	}
	if *first != *second {
		t.Fatal("chrome_auto changed ClientHelloID in one process")
	}
}

func TestRandomFingerprintIsProcessStable(t *testing.T) {
	first := GetFingerprint("random")
	second := GetFingerprint("random")
	if first == nil || second == nil {
		t.Fatal("random returned nil")
	}
	if first != second {
		t.Fatal("random returned different ClientHelloID pointers in one process")
	}
	if *first != *second {
		t.Fatal("random changed ClientHelloID in one process")
	}
}

func TestRandomizedFingerprintIsProcessStable(t *testing.T) {
	first := GetFingerprint("randomized")
	second := GetFingerprint("randomized")
	if first == nil || second == nil {
		t.Fatal("randomized returned nil")
	}
	if first != second {
		t.Fatal("randomized returned different ClientHelloID pointers in one process")
	}
	if first.Seed == nil {
		t.Fatal("randomized seed was not initialized")
	}
	if first.Seed != second.Seed {
		t.Fatal("randomized changed PRNG seed in one process")
	}
}

func TestUnknownFingerprint(t *testing.T) {
	if fingerprint := GetFingerprint("netscape999"); fingerprint != nil {
		t.Fatalf("GetFingerprint(\"netscape999\") = %v, want nil", fingerprint.Str())
	}
	if _, ok := ResolveFingerprint("netscape999"); ok {
		t.Fatal("ResolveFingerprint(\"netscape999\") returned true")
	}
}
