package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/takc923/mdns"
	"golang.org/x/net/ipv4"
)

type device struct {
	ip     string // IP address of the device
	vendor string // vendor name from mac
	mac    string // IEEE MAC-48, EUI-48 and EUI-64 form
}

// func newDevice(name string) *device {
// 	entry := device{} //{IP: "testip", Vendor: "", MAC: "testmac"}
// 	entry.ip = "testip"
// 	entry.vendor = "testvendor"
// 	entry.mac = "testmac"
// 	return &entry
// }

func main() {
	// Get a list of all interfaces.
	fmt.Println(device{ip: "testip"})

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get interfaces: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "interface %v\n", ifaces)
	fmt.Println(reflect.TypeOf(ifaces))

	r := flag.Bool("r", false, "show only Raspberry Pi device")
	wait := flag.Uint("w", 1000, "duration in milliseconds to wait for ARP responses")
	interval := flag.Uint("i", 1, "interval between ARP requests in milliseconds")
	// networkInterface := flag.String("n", "eth0", "network interface name")

	// arpscan shows results only with MAC addresses which contains `filter`.
	filter := ""
	if *r {
		filter = "b8:27:eb" // Raspberry Pi specific address
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface, filter, time.Duration(*wait)*time.Millisecond, time.Duration(*interval)*time.Millisecond); err != nil {
				fmt.Fprintf(os.Stderr, "interface %v: %v\n", iface.Name, err)
			}
		}(iface)
	}
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface, filter string, wait, interval time.Duration) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		addr = getIPNet(a)
		if addr != nil {
			break
		}
	}

	// Sanity-check that the interface has a good address.
	if addr == nil {
		return nil
	} else if addr.IP[0] == 127 || (addr.IP[0] == 169 && addr.IP[1] == 254) { // Ignore loopback addresses and link-local addresses.
		return nil
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	results := make(chan *layers.ARP, 10)
	go readARP(handle, iface, stop, results)
	defer close(stop)
	// Write our scan packets out to the handle.
	if err := writeARP(handle, iface, addr, interval); err != nil {
		fmt.Fprintf(os.Stderr, "error writing packets on %v: %v\n", iface.Name, err)
		return err
	}

	serverAddr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		return err
	}

	l, err := net.ListenMulticastUDP("udp4", iface, serverAddr)
	if err != nil {
		return err
	}

	server, err := mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{})
	if err != nil {
		return err
	}
	defer server.Close()

	var history []net.IP
	var wg sync.WaitGroup
	timeout := time.After(wait)
L:
	for {
		select {
		case arp := <-results:
			ip := net.IP(arp.SourceProtAddress)
			if contains(history, ip) {
				continue
			}
			history = append(history, ip)

			mac := net.HardwareAddr(arp.SourceHwAddress)
			if !strings.Contains(mac.String(), filter) {
				continue
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, name, _ := server.ReverseLookup(ctx, ip)

				// Note:  we might get some packets here that aren't responses to ones we've sent,
				// if for example someone else sends US an ARP request.  Doesn't much matter, though...
				// all information is good information :)
				fmt.Printf("IP %v (%v) is at %v\n", ip, name, mac)
			}()
		case <-timeout:
			break L
		}
	}
	wg.Wait()

	return nil
}

func getIPNet(addr net.Addr) *net.IPNet {
	ipNet, ok := addr.(*net.IPNet)
	if !ok {
		return nil
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil
	}

	return &net.IPNet{
		IP:   ip4,
		Mask: ipNet.Mask[len(ipNet.Mask)-4:],
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}, results chan<- *layers.ARP) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal(iface.HardwareAddr, arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			results <- arp
		}
	}
}

func contains(ips []net.IP, target net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet, interval time.Duration) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send two packets for every address because sometimes ARP packets are lost.
	dsts := ips(addr)
	dsts = append(dsts, dsts...)
	for _, ip := range dsts {
		arp.DstProtAddress = ip
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
		time.Sleep(interval)
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32(n.IP)
	mask := binary.BigEndian.Uint32(n.Mask)
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, buf[:])
	}
	return
}
