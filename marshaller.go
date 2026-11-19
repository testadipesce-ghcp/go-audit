package main

import (
	"os"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const (
	EVENT_EOE = 1320 // End of multi packet event
)

type AuditMarshaller struct {
	msgs           map[int]*AuditMessageGroup
	writer         *AuditWriter
	lastSeq        int
	missed         map[int]bool
	worstLag       int
	eventMin       uint16
	eventMax       uint16
	trackMessages  bool
	logOutOfOrder  bool
	maxOutOfOrder  int
	attempts       int
	filters        map[string]map[uint16][]*regexp.Regexp // { syscall: { mtype: [regexp, ...] } }
	eventAllow     map[uint16]bool
	eventExclude   map[uint16]bool
	substitutions  map[uint16][]AuditSubstitution  // { mtype: [substitution, ...] }
	messageFilters map[uint16][]AuditMessageFilter // { mtype: [filter, ...] }
	seqRemaps      map[uint16][]AuditSeqRemap      // { mtype: [remap, ...] }
	extraParsers   ExtraParsers
}

type AuditFilter struct {
	messageType uint16
	regex       *regexp.Regexp
	syscall     string
}

// AuditSubstitution describes a regex substitution to apply to the data
// portion of a parsed audit message of a given type
type AuditSubstitution struct {
	messageType uint16
	regex       *regexp.Regexp
	replace     string
}

// Actions for an AuditMessageFilter
const (
	FilterActionGrep    = "grep"    // keep only messages whose data matches the regex
	FilterActionExclude = "exclude" // discard messages whose data matches the regex
)

// AuditMessageFilter describes a regex test on the data of messages of a given
// type, and what to do with the message depending on the result
type AuditMessageFilter struct {
	messageType uint16
	regex       *regexp.Regexp
	action      string
}

// AuditSeqRemap describes how to replace the sequence number of a message of a
// given type: the first capture group of the regex (or the whole match if the
// regex has no groups) is parsed as an integer, and offset is added to it
type AuditSeqRemap struct {
	messageType uint16
	regex       *regexp.Regexp
	offset      int
}

// Create a new marshaller
func NewAuditMarshaller(w *AuditWriter, eventMin uint16, eventMax uint16, trackMessages, logOOO bool, maxOOO int, filters []AuditFilter, eventAllow []uint16, eventExclude []uint16, substitutions []AuditSubstitution, messageFilters []AuditMessageFilter, seqRemaps []AuditSeqRemap, extraParsers ExtraParsers) *AuditMarshaller {
	am := AuditMarshaller{
		writer:         w,
		msgs:           make(map[int]*AuditMessageGroup, 5), // It is not typical to have more than 2 message groups at any given time
		missed:         make(map[int]bool, 10),
		eventMin:       eventMin,
		eventMax:       eventMax,
		trackMessages:  trackMessages,
		logOutOfOrder:  logOOO,
		maxOutOfOrder:  maxOOO,
		filters:        make(map[string]map[uint16][]*regexp.Regexp),
		eventAllow:     make(map[uint16]bool, len(eventAllow)),
		eventExclude:   make(map[uint16]bool, len(eventExclude)),
		substitutions:  make(map[uint16][]AuditSubstitution, len(substitutions)),
		messageFilters: make(map[uint16][]AuditMessageFilter, len(messageFilters)),
		seqRemaps:      make(map[uint16][]AuditSeqRemap, len(seqRemaps)),
		extraParsers:   extraParsers,
	}

	for _, filter := range filters {
		if _, ok := am.filters[filter.syscall]; !ok {
			am.filters[filter.syscall] = make(map[uint16][]*regexp.Regexp)
		}

		if _, ok := am.filters[filter.syscall][filter.messageType]; !ok {
			am.filters[filter.syscall][filter.messageType] = []*regexp.Regexp{}
		}

		am.filters[filter.syscall][filter.messageType] = append(am.filters[filter.syscall][filter.messageType], filter.regex)
	}

	for _, t := range eventAllow {
		am.eventAllow[t] = true
	}

	for _, t := range eventExclude {
		am.eventExclude[t] = true
	}

	for _, sub := range substitutions {
		am.substitutions[sub.messageType] = append(am.substitutions[sub.messageType], sub)
	}

	for _, ex := range messageFilters {
		am.messageFilters[ex.messageType] = append(am.messageFilters[ex.messageType], ex)
	}

	for _, r := range seqRemaps {
		am.seqRemaps[r.messageType] = append(am.seqRemaps[r.messageType], r)
	}

	return &am
}

// Ingests a netlink message and likely prepares it to be logged
func (a *AuditMarshaller) Consume(nlMsg *syscall.NetlinkMessage) {
	aMsg := NewAuditMessage(nlMsg)

	if aMsg.Seq == 0 {
		// We got an invalid audit message, return the current message and reset
		a.flushOld()
		return
	}

	if a.trackMessages {
		a.detectMissing(aMsg.Seq)
	}

	t := nlMsg.Header.Type
	inRange := t >= a.eventMin && t <= a.eventMax
	// if a.eventExclude[t] || !(a.eventAllow[t] || inRange) {
	if !a.eventAllow[t] && (a.eventExclude[t] || !inRange) {
		// Drop all audit messages that aren't things we care about or end a multi packet event
		a.flushOld()
		return
	} else if t == EVENT_EOE {
		// This is end of event msg, flush the msg with that sequence and discard this one
		a.completeMessage(aMsg.Seq)
		return
	}

	if a.isDiscardedMessage(aMsg) {
		// Discard just this message; the rest of its group is unaffected
		a.flushOld()
		return
	}

	a.applySeqRemaps(aMsg)
	a.applySubstitutions(aMsg)

	if val, ok := a.msgs[aMsg.Seq]; ok {
		// Use the original AuditMessageGroup if we have one
		val.AddMessage(aMsg)
	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = NewAuditMessageGroup(aMsg)
	}
	a.extraParsers.Parse(aMsg)

	a.flushOld()
}

// Returns true if the message should be discarded per the configured message
// filters for its type. Matching is done against the original, unsubstituted data
func (a *AuditMarshaller) isDiscardedMessage(am *AuditMessage) bool {
	for _, f := range a.messageFilters[am.Type] {
		matched := f.regex.MatchString(am.Data)
		if (f.action == FilterActionGrep && !matched) || (f.action == FilterActionExclude && matched) {
			return true
		}
	}
	return false
}

// Replaces the sequence number of a message with a value extracted from its
// original (unsubstituted) data plus a configured offset. The first remap that
// matches and yields an integer wins
func (a *AuditMarshaller) applySeqRemaps(am *AuditMessage) {
	for _, r := range a.seqRemaps[am.Type] {
		m := r.regex.FindStringSubmatch(am.Data)
		if m == nil {
			continue
		}

		captured := m[0]
		if len(m) > 1 {
			captured = m[1]
		}

		n, err := strconv.Atoi(captured)
		if err != nil {
			continue
		}

		am.Seq = n + r.offset
		return
	}
}

// Applies any configured regex substitutions to the data portion of a message,
// based on its message type
func (a *AuditMarshaller) applySubstitutions(am *AuditMessage) {
	subs, ok := a.substitutions[am.Type]
	if !ok {
		return
	}

	for _, sub := range subs {
		am.Data = sub.regex.ReplaceAllString(am.Data, sub.replace)
	}
}

// Outputs any messages that are old enough
// This is because there is no indication of multi message events coming from kaudit
func (a *AuditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}

// Write a complete message group to the configured output in json format
func (a *AuditMarshaller) completeMessage(seq int) {
	var msg *AuditMessageGroup
	var ok bool

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		return
	}

	if a.dropMessage(msg) {
		delete(a.msgs, seq)
		return
	}

	if err := a.writer.Write(msg); err != nil {
		el.Println("Failed to write message. Error:", err)
		os.Exit(1)
	}

	delete(a.msgs, seq)
}

func (a *AuditMarshaller) dropMessage(msg *AuditMessageGroup) bool {
	filters, ok := a.filters[msg.Syscall]
	if !ok {
		return false
	}

	for _, msg := range msg.Msgs {
		if fg, ok := filters[msg.Type]; ok {
			for _, filter := range fg {
				if filter.MatchString(msg.Data) {
					return true
				}
			}
		}
	}

	return false
}

// Track sequence numbers and log if we suspect we missed a message
func (a *AuditMarshaller) detectMissing(seq int) {
	if seq > a.lastSeq+1 && a.lastSeq != 0 {
		// We likely leap frogged over a msg, wait until the next sequence to make sure
		for i := a.lastSeq + 1; i < seq; i++ {
			a.missed[i] = true
		}
	}

	for missedSeq := range a.missed {
		if missedSeq == seq {
			lag := a.lastSeq - missedSeq
			if lag > a.worstLag {
				a.worstLag = lag
			}

			if a.logOutOfOrder {
				el.Println("Got sequence", missedSeq, "after", lag, "messages. Worst lag so far", a.worstLag, "messages")
			}
			delete(a.missed, missedSeq)
		} else if seq-missedSeq > a.maxOutOfOrder {
			el.Printf("Likely missed sequence %d, current %d, worst message delay %d\n", missedSeq, seq, a.worstLag)
			delete(a.missed, missedSeq)
		}
	}

	if seq > a.lastSeq {
		// Keep track of the largest sequence
		a.lastSeq = seq
	}
}
