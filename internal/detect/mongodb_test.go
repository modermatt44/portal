package detect

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

func bsonDouble(name string, v float64) []byte {
	e := append([]byte{0x01}, name...)
	e = append(e, 0)
	return binary.LittleEndian.AppendUint64(e, math.Float64bits(v))
}

func bsonBool(name string, v bool) []byte {
	b := byte(0)
	if v {
		b = 1
	}
	e := append([]byte{0x08}, name...)
	return append(e, 0, b)
}

// mongoHandler emulates mongod: it answers isMaster and buildInfo OP_MSG
// commands and hangs up on anything else.
func mongoHandler(conn net.Conn) {
	for {
		var hdr [16]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(hdr[:])
		if binary.LittleEndian.Uint32(hdr[12:]) != mongoOpMsg || n > 1<<16 || n < 21 {
			return
		}
		body := make([]byte, n-16)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		doc := body[5:]
		cmd := string(doc[5 : 5+bytes.IndexByte(doc[5:], 0)]) // first element name

		var reply []byte
		switch cmd {
		case "isMaster":
			reply = bsonDoc(
				bsonBool("ismaster", true),
				bsonInt32("maxWireVersion", 21),
				// An embedded document, which bsonFields must skip.
				append(append([]byte{0x03}, "topologyVersion\x00"...), bsonDoc(bsonInt32("counter", 0))...),
				bsonString("setName", "rs0"),
				bsonDouble("ok", 1),
			)
		case "buildInfo":
			reply = bsonDoc(bsonString("version", "7.0.5"), bsonDouble("ok", 1))
		default:
			return
		}
		msg := make([]byte, 16, 16+5+len(reply))
		binary.LittleEndian.PutUint32(msg[12:], mongoOpMsg)
		msg = append(msg, 0, 0, 0, 0, 0)
		msg = append(msg, reply...)
		binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
		conn.Write(msg)
	}
}

func TestDetectMongoDB(t *testing.T) {
	t.Parallel()
	s := fakeserver.Start(t, mongoHandler)
	best := wantBest(t, detectFake(t, s), MongoDB, Confirmed)
	if best.Version != "7.0.5" || best.Details["replica_set"] != "rs0" || best.Details["max_wire_version"] != "21" {
		t.Errorf("result = %+v", best)
	}
}

func TestBSONFields(t *testing.T) {
	doc := bsonDoc(bsonString("s", "x"), bsonInt32("i", 7), bsonBool("b", true), bsonDouble("d", 1.5))
	f, err := bsonFields(doc)
	if err != nil {
		t.Fatal(err)
	}
	if f["s"] != "x" || f["i"] != int32(7) || f["b"] != true || f["d"] != 1.5 {
		t.Errorf("fields = %v", f)
	}
	for _, bad := range [][]byte{nil, {1, 0, 0}, {0xff, 0, 0, 0, 0}, doc[:len(doc)-3]} {
		if _, err := bsonFields(bad); err == nil {
			t.Errorf("bsonFields(%x) accepted a truncated document", bad)
		}
	}
}
