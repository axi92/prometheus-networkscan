// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// arpscan implements ARP scanning of all interfaces' local networks using
// gopacket and its subpackages.  This example shows, among other things:
//   - Generating and sending packet data
//   - Reading in packet data and interpreting it
//   - Use of the 'pcap' subpackage for reading/writing
package main

import (
	"bytes"
	"embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap" // needs "apt-get install libpcap-dev" on ubuntu
	"github.com/hashicorp/go-version"
	"github.com/tidwall/gjson"
)

type device struct {
	ip       string // IP address of the device
	vendor   string // vendor name from mac
	mac      string // IEEE MAC-48, EUI-48 and EUI-64 form
	lastseen int64
}

// var devices map[string]device
// m :=       make(map[string]float64)
var devices = make(map[string]device)
var bindAddress string
var bindPort int
var interfaceName string

//go:embed src
var fsEmbed embed.FS
var macData, macReadError = fsEmbed.ReadFile("src/mac-vendors-export.json")

var mutex = &sync.Mutex{}

func init() {
	flag.StringVar(&interfaceName, "interfaceName", "", "Network interface to scan. Example: enp38s0")
	flag.StringVar(&bindAddress, "bindAddress", "", "Address to bind the webserver for /metrics. Default empty = listening an all interfaces")
	flag.IntVar(&bindPort, "bindPort", 3000, "Port to bind the webserver for /metrics. Default 3000")
	flag.Parse()
	check(macReadError)
}

func main() {
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				fmt.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
	}
	handler := http.HandlerFunc(handleRequest)
	http.Handle("/metrics", handler)
	http.ListenAndServe(fmt.Sprintf("%v:%v", bindAddress, bindPort), nil)

	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	if iface.Name != interfaceName && interfaceName != "" {
		return nil
	}
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return errors.New("no good IP network found\n")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost\n")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large\n")
	}
	fmt.Printf("Using network range %v for interface %v\n", addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)
	for {
		// Write our scan packets out to the handle.
		if err := writeARP(handle, iface, addr); err != nil {
			fmt.Printf("error writing packets on %v: %v", iface.Name, err)
			return err
		}
		// We don't know exactly how long it'll take for packets to be
		// sent back to us, but 10 seconds should be more than enough
		// time ;)
		time.Sleep(10 * time.Second)
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
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
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			// devices = append(devices, device{ip: net.IP(arp.SourceProtAddress), mac: net.HardwareAddr(arp.SourceHwAddress)})

			result := gjson.Get(string(macData), "#(macPrefix=="+strings.ToUpper(fmt.Sprint(net.HardwareAddr(arp.SourceHwAddress)[:3])+")"))
			var vendor string
			if result.Exists() {
				// fmt.Println(result)
				vendor = gjson.Get(result.String(), "vendorName").String()
			} else {
				vendor = "Unknown"
			}
			mutex.Lock()
			devices[fmt.Sprint(net.IP(arp.SourceProtAddress))] = device{ip: fmt.Sprint(net.IP(arp.SourceProtAddress)), mac: fmt.Sprint(net.HardwareAddr(arp.SourceHwAddress)), vendor: vendor, lastseen: time.Now().Unix()}
			mutex.Unlock()
			for key, element := range devices {
				// fmt.Println("Key:", key, "=>", "Element:", element.lastseen)
				if time.Now().Unix()-1*60 > element.lastseen {
					mutex.Lock()
					delete(devices, key)
					mutex.Unlock()
					fmt.Print("device removed!", element, "\n")
				}
			}
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
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
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/text")
	// Sort map first so order is allways the same
	var keys = make([]string, 0, len(devices))
	for k := range devices {
		keys = append(keys, k)
	}
	sort.Sort(byVersion(keys))

	var metricName string = "networkscanner"
	w.Write([]byte(fmt.Sprintln("# HELP", metricName, "Online network devices.")))
	w.Write([]byte(fmt.Sprintln("# TYPE", metricName, "status")))
	for _, k := range keys {
		w.Write([]byte(fmt.Sprintf("%v{ip=\"%v\", mac=\"%v\", vendor=\"%v\"} 1\n", metricName, k, devices[k].mac, devices[k].vendor))) //devices[k]
	}
	return
}

type byVersion []string

func (s byVersion) Len() int {
	return len(s)
}

func (s byVersion) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byVersion) Less(i, j int) bool {
	v1, err := version.NewVersion(s[i])
	if err != nil {
		panic(err)
	}
	v2, err := version.NewVersion(s[j])
	if err != nil {
		panic(err)
	}
	return v1.LessThan(v2)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
