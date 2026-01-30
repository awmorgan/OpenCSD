package common

// Atom represents a single execution decision in a PTM Atom packet.
type Atom uint8

const (
	// AtomNotExecuted indicates the instruction was not executed (branch not taken).
	AtomNotExecuted Atom = iota
	// AtomExecuted indicates the instruction was executed (branch taken / instruction executed).
	AtomExecuted
)

func (a Atom) String() string {
	switch a {
	case AtomNotExecuted:
		return "N"
	case AtomExecuted:
		return "E"
	default:
		return "?"
	}
}
