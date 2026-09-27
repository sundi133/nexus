package rfb

import "testing"

func TestKeysymToKey(t *testing.T) {
	for _, c := range []struct {
		sym  uint32
		want Key
	}{
		{'a', Key{VK: 'A'}},
		{'C', Key{VK: 'C'}},
		{'7', Key{VK: '7'}},
		{' ', Key{VK: 0x20}},
		{0xff0d, Key{VK: 0x0d}},
		{0xff51, Key{VK: 0x25, Extended: true}},
		{0xffe3, Key{VK: 0xa2}},
		{0xffe7, Key{VK: 0x5b, Extended: true}},
		{0xffbe, Key{VK: 0x70}},
		{0xffc9, Key{VK: 0x7b}},
		{'@', Key{Char: '@'}},
		{0xe9, Key{Char: 'é'}},
		{0x10020ac, Key{Char: '€'}},
	} {
		got, ok := KeysymToKey(c.sym)
		if !ok || got != c.want {
			t.Errorf("keysym %#x: got %+v %v, want %+v", c.sym, got, ok, c.want)
		}
	}
	if _, ok := KeysymToKey(0xfe03); ok { // ISO_Level3_Shift: no Windows equivalent
		t.Error("unknown keysyms should be skipped")
	}
}
