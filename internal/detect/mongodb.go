package detect

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(mongoProber{}) }

// MongoDB wire protocol constants.
const (
	mongoOpMsg    = 2013
	mongoMaxReply = 1 << 20
)

// mongoProber sends the "isMaster" handshake command, then "buildInfo"
// for the version. Both are allowed without authentication.
type mongoProber struct{}

func (mongoProber) Name() string     { return "mongodb" }
func (mongoProber) Service() Service { return MongoDB }

// Probe sends isMaster as an OP_MSG (MongoDB 3.6+). A reply document with
// "ok" and "maxWireVersion" confirms MongoDB.
func (mongoProber) Probe(ctx context.Context, conn net.Conn, t target.Target) (*Result, error) {
	hello, err := mongoCommand(conn, 1, "isMaster")
	if err != nil {
		return nil, err
	}
	wire, hasWire := hello["maxWireVersion"]
	if _, ok := hello["ok"]; !ok || !hasWire {
		return nil, nil
	}
	r := &Result{
		Service:    MongoDB,
		Confidence: Confirmed,
		Evidence:   fmt.Sprintf("answered isMaster (maxWireVersion %v)", wire),
	}
	r.setDetail("max_wire_version", fmt.Sprint(wire))
	if name, ok := hello["setName"].(string); ok {
		r.setDetail("replica_set", name)
	}
	if msg, ok := hello["msg"].(string); ok && msg == "isdbgrid" {
		r.setDetail("role", "mongos (sharded cluster router)")
	}
	if info, err := mongoCommand(conn, 2, "buildInfo"); err == nil {
		if v, ok := info["version"].(string); ok {
			r.Version = v
		}
	}
	return r, nil
}

// mongoCommand sends {<name>: 1, $db: "admin"} and returns the top-level
// fields of the reply document.
func mongoCommand(conn net.Conn, requestID int32, name string) (map[string]any, error) {
	doc := bsonDoc(bsonInt32(name, 1), bsonString("$db", "admin"))
	msg := make([]byte, 16, 16+5+len(doc))
	binary.LittleEndian.PutUint32(msg[4:], uint32(requestID))
	binary.LittleEndian.PutUint32(msg[12:], mongoOpMsg)
	msg = append(msg, 0, 0, 0, 0) // flagBits
	msg = append(msg, 0)          // section kind 0: body
	msg = append(msg, doc...)
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	var hdr [16]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[0:])
	if n < 16+5+5 || n > mongoMaxReply || binary.LittleEndian.Uint32(hdr[12:]) != mongoOpMsg {
		return nil, errors.New("not an OP_MSG reply")
	}
	body := make([]byte, n-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	if body[4] != 0 {
		return nil, errors.New("unexpected OP_MSG section kind")
	}
	return bsonFields(body[5:])
}

func bsonDoc(elems ...[]byte) []byte {
	body := bytes.Join(elems, nil)
	doc := binary.LittleEndian.AppendUint32(nil, uint32(4+len(body)+1))
	doc = append(doc, body...)
	return append(doc, 0)
}

func bsonInt32(name string, v int32) []byte {
	e := append([]byte{0x10}, name...)
	e = append(e, 0)
	return binary.LittleEndian.AppendUint32(e, uint32(v))
}

func bsonString(name, v string) []byte {
	e := append([]byte{0x02}, name...)
	e = append(e, 0)
	e = binary.LittleEndian.AppendUint32(e, uint32(len(v)+1))
	e = append(e, v...)
	return append(e, 0)
}

// bsonFields decodes the top-level scalar fields of a BSON document.
// Nested documents, arrays and binary values are skipped and reported as
// nil.
func bsonFields(doc []byte) (map[string]any, error) {
	errShort := errors.New("truncated BSON document")
	if len(doc) < 5 {
		return nil, errShort
	}
	n := int(binary.LittleEndian.Uint32(doc))
	if n < 5 || n > len(doc) {
		return nil, errShort
	}
	doc = doc[:n-1] // drop the trailing NUL
	fields := map[string]any{}
	i := 4
	need := func(k int) error {
		if k < 0 || i+k > len(doc) {
			return errShort
		}
		return nil
	}
	for i < len(doc) {
		typ := doc[i]
		i++
		end := bytes.IndexByte(doc[i:], 0)
		if end < 0 {
			return nil, errShort
		}
		name := string(doc[i : i+end])
		i += end + 1

		var size int
		var val any
		switch typ {
		case 0x01: // double
			size = 8
			if err := need(size); err != nil {
				return nil, err
			}
			val = math.Float64frombits(binary.LittleEndian.Uint64(doc[i:]))
		case 0x02: // string
			if err := need(4); err != nil {
				return nil, err
			}
			l := int(int32(binary.LittleEndian.Uint32(doc[i:])))
			size = 4 + l
			if err := need(size); err != nil || l < 1 {
				return nil, errShort
			}
			val = string(doc[i+4 : i+4+l-1])
		case 0x03, 0x04: // document, array
			if err := need(4); err != nil {
				return nil, err
			}
			size = int(int32(binary.LittleEndian.Uint32(doc[i:])))
		case 0x05: // binary
			if err := need(4); err != nil {
				return nil, err
			}
			size = 4 + 1 + int(int32(binary.LittleEndian.Uint32(doc[i:])))
		case 0x07: // ObjectId
			size = 12
		case 0x08: // bool
			size = 1
			if err := need(size); err != nil {
				return nil, err
			}
			val = doc[i] == 1
		case 0x09, 0x11: // UTC datetime, timestamp
			size = 8
		case 0x0a: // null
		case 0x10: // int32
			size = 4
			if err := need(size); err != nil {
				return nil, err
			}
			val = int32(binary.LittleEndian.Uint32(doc[i:]))
		case 0x12: // int64
			size = 8
			if err := need(size); err != nil {
				return nil, err
			}
			val = int64(binary.LittleEndian.Uint64(doc[i:]))
		case 0x13: // decimal128
			size = 16
		default:
			return fields, errors.New("unsupported BSON type 0x" + strconv.FormatInt(int64(typ), 16))
		}
		if err := need(size); err != nil {
			return nil, err
		}
		fields[name] = val
		i += size
	}
	return fields, nil
}
