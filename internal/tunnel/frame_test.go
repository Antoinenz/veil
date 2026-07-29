package tunnel

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{Type: TypeHandshakeInit, Counter: 0, Payload: []byte("hello noise")},
		{Type: TypeData, Counter: 42, Payload: bytes.Repeat([]byte{0xAB}, 1400)},
		{Type: TypeKeepalive, Counter: 1 << 40, Payload: nil},
		{Type: TypeClose, Counter: ^uint64(0), Payload: []byte{}},
	}
	for _, in := range cases {
		enc, err := in.Encode(nil)
		if err != nil {
			t.Fatalf("encode %v: %v", in.Type, err)
		}
		out, n, err := Decode(enc)
		if err != nil {
			t.Fatalf("decode %v: %v", in.Type, err)
		}
		if n != len(enc) {
			t.Fatalf("%v: consumed %d, want %d", in.Type, n, len(enc))
		}
		if out.Type != in.Type || out.Counter != in.Counter {
			t.Fatalf("header mismatch: got %+v want type=%v counter=%d", out, in.Type, in.Counter)
		}
		if !bytes.Equal(out.Payload, in.Payload) {
			t.Fatalf("%v: payload mismatch", in.Type)
		}
	}
}

func TestDecodeShortHeader(t *testing.T) {
	if _, _, err := Decode([]byte{1, 2, 3}); err != ErrShortHeader {
		t.Fatalf("got %v, want ErrShortHeader", err)
	}
}

func TestDecodeTruncatedPayload(t *testing.T) {
	enc, _ := Frame{Type: TypeData, Payload: []byte("0123456789")}.Encode(nil)
	if _, _, err := Decode(enc[:len(enc)-3]); err != ErrShortHeader {
		t.Fatalf("got %v, want ErrShortHeader", err)
	}
}

func TestDecodeBadVersion(t *testing.T) {
	enc, _ := Frame{Type: TypeData, Payload: []byte("x")}.Encode(nil)
	enc[0] = 9
	if _, _, err := Decode(enc); err != ErrBadVersion {
		t.Fatalf("got %v, want ErrBadVersion", err)
	}
}

func TestStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Frame{Type: TypeData, Counter: 7, Payload: []byte("stream payload")}
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Counter != want.Counter || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("stream round-trip mismatch: got %+v want %+v", got, want)
	}
}
