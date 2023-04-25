package main

import (
	"acl/rule"
	"fmt"
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags "-O2 -g -Wall -Werror" bpf ./src/acl.c -- -I ./src/headers
// const mapKey uint32 = 0

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
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

	rule1 := rule.Rule{
		ID:     1,
		Sip:    []string{"20.1.0.10"},
		Dip:    []string{"20.1.0.11"},
		Action: 2,
	}

	rule1.LoadAction(objs.bpfMaps.MatchActionHashMap)
	rule1.LoadSip(objs.bpfMaps.MatchAddrSrcHashMap)
	rule1.LoadDip(objs.bpfMaps.MatchAddrDstHashMap)
	// rule1.LoadDport(objs.bpfMaps.MatchDportHashMap)
	// rule1.LoadSport(objs.bpfMaps.MatchSportHashMap)

	itr := objs.bpfMaps.MatchAddrSrcHashMap.Iterate()
	key := rule.AddrHash{}
	val := rule.MatchVal{}
	for itr.Next(&key, &val) {
		fmt.Printf("src %+v %+v \n", key, val)
	}

	itr = objs.bpfMaps.MatchAddrDstHashMap.Iterate()
	for itr.Next(&key, &val) {
		fmt.Printf("dst %+v %+v \n", key, val)
	}
	type Log struct {
		ID rule.BitMap
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
