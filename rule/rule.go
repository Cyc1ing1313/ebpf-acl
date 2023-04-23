package rule

import "github.com/cilium/ebpf"


type Rule struct {
	ID int
	Sip []string
	Dip []string
	Action string
	Dport []int
	Sport []int
}

func (r *Rule) Load(mp ebpf.Map) {
	mp.Update()
}

func (r *Rule) String() {

}