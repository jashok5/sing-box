package protocol

import (
	"net"
	"sort"

	"github.com/Dreamacro/clash/transport/ssr/tools"
)

func init() {
	register("auth_chain_b", newAuthChainB, 4)
}

type authChainB struct {
	*authChainA
	dataSizeList  []int
	dataSizeList2 []int
}

func newAuthChainB(b *Base) Protocol {
	a := &authChainB{
		authChainA: &authChainA{
			Base:     b,
			authData: &authData{},
			userData: &userData{},
			salt:     "auth_chain_b",
		},
	}
	a.initUserData()
	return a
}

func (a *authChainB) StreamConn(c net.Conn, iv []byte) net.Conn {
	p := &authChainB{
		authChainA: &authChainA{
			Base:     a.Base,
			authData: a.next(),
			userData: a.userData,
			salt:     a.salt,
			packID:   1,
			recvID:   1,
		},
	}
	p.iv = iv
	p.randDataLength = p.getRandLength
	p.initDataSize()
	return &Conn{Conn: c, Protocol: p}
}

func (a *authChainB) initDataSize() {
	a.randomServer.InitFromBin(a.Key)
	length := int(a.randomServer.Next()%8 + 4)
	if cap(a.dataSizeList) < length {
		a.dataSizeList = make([]int, length)
	} else {
		a.dataSizeList = a.dataSizeList[:length]
	}
	for i := 0; i < length; i++ {
		a.dataSizeList[i] = int(a.randomServer.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(a.dataSizeList)

	length = int(a.randomServer.Next()%16 + 8)
	if cap(a.dataSizeList2) < length {
		a.dataSizeList2 = make([]int, length)
	} else {
		a.dataSizeList2 = a.dataSizeList2[:length]
	}
	for i := 0; i < length; i++ {
		a.dataSizeList2[i] = int(a.randomServer.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(a.dataSizeList2)
}

func (a *authChainB) getRandLength(length int, lashHash []byte, random *tools.XorShift128Plus) int {
	if length >= 1440 {
		return 0
	}
	random.InitFromBinAndLength(lashHash, length)
	listLength := len(a.dataSizeList)
	pos := sort.Search(listLength, func(i int) bool { return a.dataSizeList[i] >= length+a.Overhead })
	finalPos := pos + int(random.Next()%uint64(listLength))
	if finalPos < listLength {
		return a.dataSizeList[finalPos] - length - a.Overhead
	}

	list2Length := len(a.dataSizeList2)
	pos = sort.Search(list2Length, func(i int) bool { return a.dataSizeList2[i] >= length+a.Overhead })
	finalPos = pos + int(random.Next()%uint64(list2Length))
	if finalPos < list2Length {
		return a.dataSizeList2[finalPos] - length - a.Overhead
	}
	if finalPos < pos+list2Length-1 {
		return 0
	}
	if length > 1300 {
		return int(random.Next() % 31)
	}
	if length > 900 {
		return int(random.Next() % 127)
	}
	if length > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}
