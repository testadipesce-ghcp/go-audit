package main

import (
	"bytes"
	"errors"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMarshallerConstants(t *testing.T) {
	assert.Equal(t, 1320, EVENT_EOE)
}

func TestAuditMarshaller_Consume(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1100), uint16(1399), false, false, 0, []AuditFilter{}, nil, nil, nil, nil, nil, nil, nil)

	// Flush group on 1320
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1300),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:1): hi there"),
	})

	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1301),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:1): hi there"),
	})

	m.Consume(new1320("1"))

	assert.Equal(
		t,
		"{\"sequence\":1,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"hi there\"},{\"type\":1301,\"data\":\"hi there\"}],\"uid_map\":{}}\n",
		w.String(),
	)
	assert.Equal(t, 0, len(m.msgs))

	// Ignore below 1100
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1099),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:2): hi there"),
	})

	assert.Equal(t, 0, len(m.msgs))

	// Ignore above 1399
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1400),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:3): hi there"),
	})

	assert.Equal(t, 0, len(m.msgs))

	// Ignore sequences of 0
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1400),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:0): hi there"),
	})

	assert.Equal(t, 0, len(m.msgs))

	// Should flush old msgs after 2 seconds
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1300),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:4): hi there"),
	})

	start := time.Now()
	for len(m.msgs) != 0 {
		m.Consume(new1320("0"))
	}

	assert.Equal(t, "{\"sequence\":4,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"hi there\"}],\"uid_map\":{}}\n", w.String())
	expected := start.Add(time.Second * 2)
	assert.True(t, expected.Equal(time.Now()) || expected.Before(time.Now()), "Should have taken at least 2 seconds to flush")
	assert.Equal(t, 0, len(m.msgs))
}

func TestAuditMarshaller_Consume_EventAllowExclude(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, []uint16{1103}, []uint16{1305}, nil, nil, nil, nil, nil)

	// Allow-listed type outside [min, max] is kept
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1103)},
		Data:   []byte("audit(10000001:1): hi there"),
	})
	m.Consume(new1320("1"))
	assert.Equal(
		t,
		"{\"sequence\":1,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1103,\"data\":\"hi there\"}],\"uid_map\":{}}\n",
		w.String(),
	)
	assert.Equal(t, 0, len(m.msgs))

	// Excluded type inside [min, max] is dropped
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1305)},
		Data:   []byte("audit(10000001:2): hi there"),
	})
	assert.Equal(t, 0, len(m.msgs))
	assert.Equal(t, "", w.String())

	// Type in both allow and exclude is kept (allow wins)
	w.Reset()
	m2 := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, []uint16{1305}, []uint16{1305}, nil, nil, nil, nil, nil)
	m2.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1305)},
		Data:   []byte("audit(10000001:3): hi there"),
	})
	m2.Consume(new1320("3"))
	assert.Equal(
		t,
		"{\"sequence\":3,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1305,\"data\":\"hi there\"}],\"uid_map\":{}}\n",
		w.String(),
	)
	assert.Equal(t, 0, len(m2.msgs))
}

func TestAuditMarshaller_Consume_Substitutions(t *testing.T) {
	w := &bytes.Buffer{}
	subs := []AuditSubstitution{
		{messageType: uint16(1302), regex: regexp.MustCompile(`name="[^"]*"`), replace: `name="REDACTED"`},
		{messageType: uint16(1302), regex: regexp.MustCompile(`cwd="[^"]*"`), replace: `cwd="REDACTED"`},
	}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, nil, nil, subs, nil, nil, nil, nil)

	// Message type with substitutions configured has its data rewritten,
	// both substitutions apply in order
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1302)},
		Data:   []byte(`audit(10000001:1): name="secret.txt" cwd="/home/user"`),
	})
	m.Consume(new1320("1"))
	assert.Equal(
		t,
		"{\"sequence\":1,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1302,\"data\":\"name=\\\"REDACTED\\\" cwd=\\\"REDACTED\\\"\"}],\"uid_map\":{}}\n",
		w.String(),
	)

	// Message type without substitutions configured is left untouched
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1300)},
		Data:   []byte(`audit(10000001:2): name="secret.txt"`),
	})
	m.Consume(new1320("2"))
	assert.Equal(
		t,
		"{\"sequence\":2,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"name=\\\"secret.txt\\\"\"}],\"uid_map\":{}}\n",
		w.String(),
	)
}

func TestAuditMarshaller_Consume_MessageFilters(t *testing.T) {
	w := &bytes.Buffer{}
	excl := []AuditMessageFilter{
		{messageType: uint16(1302), regex: regexp.MustCompile(`name="/tmp/[^"]*"`), action: FilterActionExclude},
		{messageType: uint16(1300), regex: regexp.MustCompile(`(name="[^"]*") (keep)`), action: FilterActionGrep},
	}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, nil, nil, nil, excl, nil, nil, nil)

	// A matching message is discarded, the rest of the group is kept
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1302)},
		Data:   []byte(`audit(10000001:1): name="/tmp/x"`),
	})
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1300)},
		Data:   []byte(`audit(10000001:1): name="/tmp/x" keep`),
	})
	m.Consume(new1320("1"))
	assert.Equal(
		t,
		"{\"sequence\":1,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"name=\\\"/tmp/x\\\";keep\"}],\"uid_map\":{}}\n",
		w.String(),
	)

	// A non-matching message of the same type is kept
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1302)},
		Data:   []byte(`audit(10000001:2): name="/etc/x"`),
	})
	m.Consume(new1320("2"))
	assert.Contains(t, w.String(), `"type":1302`)

	// grep: a non-matching message is discarded
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1300)},
		Data:   []byte(`audit(10000001:3): name="x"`),
	})
	m.Consume(new1320("3"))
	assert.Equal(t, "", w.String())
}

func TestAuditMarshaller_Consume_SingleMessageEvents(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, nil, nil, nil, nil, nil, []uint16{1305}, nil)

	// A single message type is written immediately, without an EOE
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1305)},
		Data:   []byte(`audit(10000001:1): a=b`),
	})
	assert.Contains(t, w.String(), `"type":1305`)
	assert.NotContains(t, m.msgs, 1)

	// Other types still wait for the EOE
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1300)},
		Data:   []byte(`audit(10000001:2): a=b`),
	})
	assert.Equal(t, "", w.String())
	assert.Contains(t, m.msgs, 2)
}

func TestAuditMarshaller_Consume_SeqRemaps(t *testing.T) {
	w := &bytes.Buffer{}
	remaps := []AuditSeqRemap{
		{messageType: uint16(1302), regex: regexp.MustCompile(`ref=(\d+)`)},
		{messageType: uint16(1300), regex: regexp.MustCompile(`ref=(\w+)`)},
	}
	m := NewAuditMarshaller(NewAuditWriter(w, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, nil, nil, nil, nil, remaps, nil, nil)

	// Negated captured integer replaces the sequence number
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1302)},
		Data:   []byte(`audit(10000001:1): ref=10`),
	})
	assert.Contains(t, m.msgs, -10)
	assert.NotContains(t, m.msgs, 1)

	// Non-integer capture leaves the sequence number untouched
	w.Reset()
	m.Consume(&syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(1300)},
		Data:   []byte(`audit(10000001:2): ref=abc`),
	})
	m.Consume(new1320("2"))
	assert.Contains(t, w.String(), `"sequence":2,`)
}

func TestAuditMarshaller_completeMessage(t *testing.T) {
	//TODO: cant test because completeMessage calls exit
	t.Skip()
	return
	// lb, elb := hookLogger()
	// m := NewAuditMarshaller(NewAuditWriter(&FailWriter{}, 1), uint16(1300), uint16(1399), false, false, 0, []AuditFilter{}, nil, nil, nil, nil, nil, nil)

	// m.Consume(&syscall.NetlinkMessage{
	// 	Header: syscall.NlMsghdr{
	// 		Len:   uint32(44),
	// 		Type:  uint16(1300),
	// 		Flags: uint16(0),
	// 		Seq:   uint32(0),
	// 		Pid:   uint32(0),
	// 	},
	// 	Data: []byte("audit(10000001:4): hi there"),
	// })

	// m.completeMessage(4)
	// assert.Equal(t, "!", lb.String())
	// assert.Equal(t, "!", elb.String())
}

func new1320(seq string) *syscall.NetlinkMessage {
	return &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1320),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:" + seq + "): "),
	}
}

type FailWriter struct{}

func (f *FailWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("derp")
}
