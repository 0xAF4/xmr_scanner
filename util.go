package main

import (
	"net"
	"strconv"
)

type IP []byte

func SplitHostPort(host string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, err
	}
	return net.ParseIP(host), uint16(port), nil
}

// func ExtractIPFromHosts(hosts []string) ([]string, error) {
// 	var ipss []string
// 	for _, node := range hosts {
// 		host, _, _ := net.SplitHostPort(node)
// 		ips, err := net.LookupIP(host)
// 		if err == nil {
// 			for _, ip := range ips {
// 				ipss = append(ipss, ip.String())
// 			}
// 		}
// 	}
// 	if len(ipss) == 0 {
// 		return nil, errors.New("no valid ip found")
// 	}
// 	return ipss, nil
// }
