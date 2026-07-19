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
	for _, name := range []string{"yandex", "yandex_auto", "helloyandex_auto"} {
		fingerprint := GetFingerprint(name)
		if fingerprint == nil {
			t.Fatalf("GetFingerprint(%q) returned nil", name)
		}
		if *fingerprint != utls.HelloChrome_Auto {
			t.Fatalf("GetFingerprint(%q) = %v, want %v", name, fingerprint.Str(), utls.HelloChrome_Auto.Str())
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
	if fingerprint := GetFingerprint("chrome999"); fingerprint != nil {
		t.Fatalf("GetFingerprint(\"chrome999\") = %v, want nil", fingerprint.Str())
	}
	if _, ok := ResolveFingerprint("chrome999"); ok {
		t.Fatal("ResolveFingerprint(\"chrome999\") returned true")
	}
}
