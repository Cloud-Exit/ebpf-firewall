package firewall

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"path"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tcActOK   = 0
	tcActShot = 2

	ethPIP     = 0x0800
	ipProtoTCP = 6
	ipProtoUDP = 17
)

type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

type Objects struct {
	Program        *ebpf.Program `ebpf:"ingress_filter"`
	AllowedSources *ebpf.Map     `ebpf:"allowed_sources"`
	ProtectedPorts *ebpf.Map     `ebpf:"protected_ports"`
	Settings       *ebpf.Map     `ebpf:"settings"`
}

func (o *Objects) Close() {
	if o.Program != nil {
		o.Program.Close()
	}
	if o.AllowedSources != nil {
		o.AllowedSources.Close()
	}
	if o.ProtectedPorts != nil {
		o.ProtectedPorts.Close()
	}
	if o.Settings != nil {
		o.Settings.Close()
	}
}

type Engine struct {
	objects *Objects
	logger  *log.Logger

	mu       sync.Mutex
	attached map[string]link.Link
}

func New(maxEntries uint32, logger *log.Logger) (*Engine, error) {
	if maxEntries == 0 {
		return nil, fmt.Errorf("maxEntries must be greater than zero")
	}
	if logger == nil {
		logger = log.Default()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Printf("unable to remove memlock limit, continuing with current limit: %v", err)
	}

	spec := collectionSpec(maxEntries)
	objects := &Objects{}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	return &Engine{
		objects:  objects,
		logger:   logger,
		attached: map[string]link.Link{},
	}, nil
}

func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, l := range e.attached {
		l.Close()
	}
	e.objects.Close()
}

func (e *Engine) Reconcile(ctx context.Context, ports []uint16, protectAllPorts bool, prefixes []netip.Prefix, interfaceGlobs []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := replacePorts(e.objects.ProtectedPorts, e.objects.Settings, ports, protectAllPorts); err != nil {
		return fmt.Errorf("update protected ports map: %w", err)
	}
	if err := replaceAllowlist(e.objects.AllowedSources, prefixes); err != nil {
		return fmt.Errorf("update allowlist map: %w", err)
	}
	if err := e.attachMatchingInterfaces(interfaceGlobs); err != nil {
		return err
	}

	return nil
}

func (e *Engine) attachMatchingInterfaces(globs []string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}

	names := []string{}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || attrs.Name == "lo" {
			continue
		}
		if matchesAny(attrs.Name, globs) {
			names = append(names, attrs.Name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		if _, ok := e.attached[name]; ok {
			continue
		}
		iface, err := netlink.LinkByName(name)
		if err != nil {
			return fmt.Errorf("load interface %s: %w", name, err)
		}
		l, err := attach(iface, e.objects.Program)
		if err != nil {
			return fmt.Errorf("attach tcx ingress filter to %s: %w", name, err)
		}
		e.attached[name] = l
		e.logger.Printf("attached ingress eBPF filter interface=%s", name)
	}

	return nil
}

func matchesAny(name string, globs []string) bool {
	for _, glob := range globs {
		matched, err := path.Match(glob, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func attach(iface netlink.Link, program *ebpf.Program) (link.Link, error) {
	return link.AttachTCX(link.TCXOptions{
		Interface: iface.Attrs().Index,
		Program:   program,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Tail(),
	})
}

func replacePorts(m *ebpf.Map, settings *ebpf.Map, ports []uint16, protectAllPorts bool) error {
	if err := clearMap[uint16](m); err != nil {
		return err
	}

	var settingsKey uint32
	var allPortsValue uint8
	if protectAllPorts {
		allPortsValue = 1
	}
	if err := settings.Update(settingsKey, allPortsValue, ebpf.UpdateAny); err != nil {
		return err
	}

	var value uint8 = 1
	for _, port := range ports {
		if err := m.Update(port, value, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func replaceAllowlist(m *ebpf.Map, prefixes []netip.Prefix) error {
	if err := clearMap[lpmKey](m); err != nil {
		return err
	}

	var value uint8 = 1
	for _, prefix := range prefixes {
		key := lpmKeyFromPrefix(prefix)
		if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func lpmKeyFromPrefix(prefix netip.Prefix) lpmKey {
	addr := prefix.Masked().Addr().As4()
	return lpmKey{
		PrefixLen: uint32(prefix.Bits()),
		Addr:      addr,
	}
}

func clearMap[K any](m *ebpf.Map) error {
	var key K
	var value uint8
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return iter.Err()
}

func collectionSpec(maxEntries uint32) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"allowed_sources": {
				Type:       ebpf.LPMTrie,
				KeySize:    8,
				ValueSize:  1,
				MaxEntries: maxEntries,
				Flags:      unix.BPF_F_NO_PREALLOC,
			},
			"protected_ports": {
				Type:       ebpf.Hash,
				KeySize:    2,
				ValueSize:  1,
				MaxEntries: 1024,
			},
			"settings": {
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  1,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"ingress_filter": {
				Type:         ebpf.SchedCLS,
				Instructions: ingressInstructions(),
				License:      "MIT",
			},
		},
	}
}

func ingressInstructions() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),

		asm.LoadAbs(12, asm.Half),
		asm.JNE.Imm(asm.R0, ethPIP, "allow"),

		asm.LoadAbs(23, asm.Byte),
		asm.Mov.Reg(asm.R8, asm.R0), // save protocol; R8 used below for TCP flag check
		asm.JEq.Imm(asm.R0, ipProtoTCP, "parse_ports"),
		asm.JNE.Imm(asm.R0, ipProtoUDP, "allow"),

		asm.LoadAbs(20, asm.Half).WithSymbol("parse_ports"),
		asm.JSet.Imm(asm.R0, 0x3fff, "drop"),

		asm.LoadAbs(14, asm.Byte),
		asm.And.Imm(asm.R0, 0x0f),
		asm.JLT.Imm(asm.R0, 5, "drop"),
		asm.LSh.Imm(asm.R0, 2),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.Add.Imm(asm.R7, 14),

		// For TCP, only enforce the allowlist on new inbound connections (pure SYN).
		// Packets that are responses to connections initiated by the node (established,
		// SYN-ACK, FIN, RST, etc.) are let through unconditionally, which fixes DNS,
		// image pulls, API server responses, and konnectivity without requiring their
		// source IPs in the allowlist.
		asm.JNE.Imm(asm.R8, ipProtoTCP, "load_dport"),
		asm.LoadInd(asm.R0, asm.R7, 13, asm.Byte), // TCP flags byte
		asm.And.Imm(asm.R0, 0x12),                  // isolate SYN(0x02) and ACK(0x10)
		asm.JNE.Imm(asm.R0, 0x02, "allow"),          // not a pure SYN → allow

		asm.LoadInd(asm.R0, asm.R7, 2, asm.Half).WithSymbol("load_dport"),
		asm.StoreMem(asm.R10, -2, asm.R0, asm.Half),

		asm.StoreImm(asm.R10, -12, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("settings"),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "check_port_map"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Byte),
		asm.JNE.Imm(asm.R0, 0, "check_source"),

		// fix: label must be on LoadMapPtr so R1 is always loaded before the lookup,
		// even when the settings map returned NULL and we jumped here directly.
		asm.LoadMapPtr(asm.R1, 0).WithReference("protected_ports").WithSymbol("check_port_map"),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -2),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),

		asm.LoadAbs(26, asm.Word).WithSymbol("check_source"),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreImm(asm.R10, -8, 32, asm.Word),
		asm.StoreMem(asm.R10, -4, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference("allowed_sources"),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "allow"),

		asm.Mov.Imm(asm.R0, tcActShot).WithSymbol("drop"),
		asm.Return(),

		asm.Mov.Imm(asm.R0, tcActOK).WithSymbol("allow"),
		asm.Return(),
	}
}

func InterfaceNames() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	return names, nil
}
