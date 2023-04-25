package rule

import (
	"fmt"
	"math"
	"net"

	"github.com/cilium/ebpf"
)

type Rule struct {
	ID     int
	Sip    []string
	Dip    []string
	Action int
	Dport  []int
	Sport  []int
}

//1 block 2 accept

func (r *Rule) LoadAction(mp *ebpf.Map) error {
	bits := BitMap{}
	bits.Set(r.ID)


	return mp.Put(bits.ToActionKey(), ActionVal{
		Action: uint32(r.Action),
	})
}

func (r *Rule) LoadSip(mp *ebpf.Map) error {
	bits := BitMap{}
	bits.Set(r.ID)
	for _, sip := range r.Sip {
		err := mp.Put(AddrHash{
			IP: uint82uint32(IP2Uint8Arr(net.ParseIP(sip).To4())),
		}, MatchVal{
			Bits: bits,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) LoadDip(mp *ebpf.Map) error {
	bits := BitMap{}
	bits.Set(r.ID)
	for _, dip := range r.Dip {
		err := mp.Put(AddrHash{
			IP: uint82uint32(IP2Uint8Arr(net.ParseIP(dip).To4())),
		}, MatchVal{
			Bits: bits,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) LoadSport(mp *ebpf.Map) error {
	bits := BitMap{}
	bits.Set(r.ID)
	for _, sport := range r.Sport {
		err := mp.Put(IntegerHash{
			Key:uint32(sport),
		}, MatchVal{
			Bits: bits,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) LoadDport(mp *ebpf.Map) error {
	bits := BitMap{}
	bits.Set(r.ID)
	for _, dport := range r.Dport {
		err := mp.Put(IntegerHash{
			Key:uint32(dport),
		}, MatchVal{
			Bits: bits,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

type LPMKey struct {
	Prefixlen uint32
	Addr      [4]uint8
}

type ActionKey struct {
	Offset uint64
	Bits uint64
}

type ActionVal struct {
	Action uint32
}

type AddrHash struct {
	IP uint32
}

type IntegerHash struct {
	Key uint32
}

type MatchVal struct {
	Bits [8]uint64
}

type BitMap [8]uint64



func (b *BitMap) Set(offset int) {
	if offset >= 8*64 {
		return
	}
	b[offset/64] = (b[offset/64] | (1 << (64 - (offset % 64) - 1)))
}

func (b *BitMap) ToActionKey() ActionKey {
	for i := 0; i < 8; i++ {
		if b[i] > 0 {
			return ActionKey{
				Offset: uint64(i),
				Bits: b[i],
			}
		}
	}
	return ActionKey{}
}

func (b *BitMap) ToOffSet() int {
	for i := 0; i < 8; i++ {
		if b[i] > 0 {
			return i*64 + (63 - int(math.Log2(float64(b[i]&(-b[i])))))
		}
	}
	return -1
}

func (b *BitMap) Print() {
	for i := 0; i < 8; i++ {
		fmt.Printf("%b\n", b[i])
	}
}

func (b *BitMap) Clear(offset int) {

}

func IP2Uint8Arr(ip net.IP) [4]uint8 {
	arr := [4]uint8{}
	for i, v := range ip {
		arr[i] = v
	}
	return arr
}

func uint82uint32(b [4]uint8) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
