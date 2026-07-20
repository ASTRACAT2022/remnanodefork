package padding

import "testing"

func BenchmarkPadding(b *testing.B) {
	p := make([]byte, 128)
	for i := 0; i < b.N; i++ {
		if _, _, e := Add(Balanced, p, 64); e != nil {
			b.Fatal(e)
		}
	}
}
