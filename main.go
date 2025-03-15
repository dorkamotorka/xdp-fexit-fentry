package main

import (
	"log"
	"net"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp xdp.c

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	ifi, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", device, err)
	}

	spec, err := loadXdp()
	if err != nil {
		log.Fatalf("Failed to load xdp bpf spec: %v", err)
		return
	}

	xdpDummy := spec.Programs["dummy"]
	dummyProg, err := ebpf.NewProgram(xdpDummy)
	if err != nil {
		log.Fatalf("Failed to create dummy program: %v", err)
	}
	defer dummyProg.Close()

	// Get function name of the dummy program to attach fentry/fexit hooks
	var funcName string
	info, err := dummyProg.Info()
        if err != nil {
                log.Fatalf("failed to get program info: %w", err)
        }

        if _, ok := info.BTFID(); !ok {
                log.Fatalf("program does not have BTF ID")
        }

        insns, err := info.Instructions()
        if err != nil {
                log.Fatalf("failed to get program instructions: %w", err)
        }

        for _, insn := range insns {
                if sym := insn.Symbol(); sym != "" {
                        funcName = sym
                }
        }

	// Configure fentry/fexit hooks target
	xdpFentry := spec.Programs["fentry_xdp"]
	xdpFentry.AttachTarget = dummyProg
	xdpFentry.AttachTo = funcName
	xdpFexit := spec.Programs["fexit_xdp"]
	xdpFexit.AttachTarget = dummyProg
	xdpFexit.AttachTo = funcName

	// Now load and assign eBPF program 
	// We couldn't use loadXdpObjects directly since it doesn't allow us to modify spec like AttachTarget, AttachTo before loading
	var obj xdpObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%-20v", err, ve)
		} else {
			log.Fatalf("Failed to load bpf obj: %v", err)
		}
	}
	defer obj.Close()

	// Attach dummy XDP program to trace
	xdplink, err := link.AttachXDP(link.XDPOptions{
		Program:   dummyProg,
		Interface: ifi.Index,
		//Flags: link.XDPDriverMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()

	// Attach fentry to XDP
	fentry, err := link.AttachTracing(link.TracingOptions{
                Program:   obj.FentryXdp,
                //AttachType: ebpf.AttachTraceFEntry,
        })
        if err != nil {
                log.Fatalf("Failed to attach fentry program: %v", err)
        }
        defer fentry.Close()

	fexit, err := link.AttachTracing(link.TracingOptions{
                Program:   obj.FexitXdp,
                //AttachType: ebpf.AttachTraceFExit,
        })
        if err != nil {
                log.Fatalf("Failed to attach fexit program: %v", err)
        }
        defer fexit.Close()

	log.Println("Programs attached and running...")
	log.Printf("Try sending some dummy network packet to %s interface.", device)

	select {}
}
