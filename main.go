package main

import (
	"fmt"
	"log"
	"math"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror" bpf ./src/acl.c -- -I ./src/headers
// const mapKey uint32 = 0
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

type LPMKey struct {
	prefixlen uint32
	addr      [4]uint8
}

type AddrHash struct {
	IP uint32
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

func main() {
	// Name of the kernel function to trace.
	// fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	eth0, _ := netlink.LinkByName("veth0")
	// qdisc := netlink.NewPrio(
	// 	netlink.QdiscAttrs{
	// 		LinkIndex: eth0.Attrs().Index,
	// 		Handle:    netlink.MakeHandle(0xffff, 0),
	// 		Parent:    netlink.HANDLE_ROOT,
	// 	},
	// )
	// if err := netlink.QdiscAdd(qdisc); err != nil {
	// 	fmt.Printf("QdiscAdd error %+v", err)
	// 	return
	// }
	// defer netlink.QdiscDel(qdisc)

	attr := netlink.FilterAttrs{
		LinkIndex: eth0.Attrs().Index,
		Protocol:  unix.ETH_P_ALL,
		Parent:    netlink.MakeHandle(0xffff, 0),
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  attr,
		Fd:           objs.bpfPrograms.AclMatch.FD(),
		Name:         objs.bpfPrograms.AclMatch.String(),
		DirectAction: true,
	}

	err := netlink.FilterAdd(filter)
	if err != nil {
		fmt.Printf("FilterAdd error %+v\n", err)
		return
	}
	defer netlink.FilterDel(filter)

	bits := BitMap{}
	bits.Set(23)

	err = objs.bpfMaps.MatchAddrSrcHashMap.Put(AddrHash{
		IP: uint82uint32(IP2Uint8Arr(net.ParseIP("20.1.0.10").To4())),
	}, MatchVal{
		Bits: bits,
	})
	if err != nil {
		fmt.Printf("bpf map set error %+v", err)
		return
	}

	err = objs.bpfMaps.MatchAddrDstHashMap.Put(AddrHash{
		IP: uint82uint32(IP2Uint8Arr(net.ParseIP("20.1.0.11").To4())),
	}, MatchVal{
		Bits: bits,
	})
	if err != nil {
		fmt.Printf("bpf map set error %+v", err)
		return
	}

	itr := objs.bpfMaps.MatchAddrSrcHashMap.Iterate()
	key := AddrHash{}
	val := MatchVal{}
	for itr.Next(&key, &val) {
		fmt.Printf("src %+v %+v \n", key, val)
	}

	itr = objs.bpfMaps.MatchAddrDstHashMap.Iterate()
	for itr.Next(&key, &val) {
		fmt.Printf("dst %+v %+v \n", key, val)
	}
	// r, err := perf.NewReader(objs.LogPerfEventArr, 1)
	// if err != nil {
	// 	fmt.Printf("NewReader error: %+v", err)
	// }

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	// kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	// ticker := time.NewTicker(1 * time.Second)
	// defer ticker.Stop()

	// log.Println("Waiting for events..")

	type Log struct {
		ID BitMap
	}
	reader, err := perf.NewReader(objs.bpfMaps.LogPerf, 4096)
	if err != nil {
		fmt.Printf("%+v", err)
		return
	}
	for range time.Tick(time.Second) {
		r, err := reader.Read()
		if err != nil {
			fmt.Printf("error %+v", err)
			continue
		}
		log := (*Log)(unsafe.Pointer(&(r.RawSample)[0]))
		fmt.Printf("hit rule %d\n", (*log).ID.ToOffSet())
	}
	select {}
}
