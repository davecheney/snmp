package snmp

type ObjectName []int
type OctetString []byte

type VarBind struct {
	Name ObjectName
	Value interface{}
}

type GetRequest struct {
	RequestId int32
	ErrorStatus int
	ErrorIndex int
	VarBindList []VarBind
}

type Message struct {
	Version int
	Community OctetString
	Data interface{}
}

func NewOctetString(s string) []byte {
	b := make([]byte, len(s))
	for i, c := range s {
		b[i] = byte(c)
	}
	return b
}

type GetNextRequest struct {
	RequestId int32
	ErrorStatus int
	ErrorIndex int
	VarBindList []VarBind
}