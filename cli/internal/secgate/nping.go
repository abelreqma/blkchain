package secgate

import (
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

func npingViolation(name string, args []string) (Decision, bool) {
	if name != "nping" {
		return Decision{}, false
	}
	if err := validNpingProbe(args); err != nil {
		return Decision{Reason: "nping " + err.Error()}, true
	}
	return Decision{}, false
}

func validNpingProbe(args []string) error {
	mode, target, flags, data := "", "", "", ""
	count, rate, port, sourcePort := -1, -1, -1, -1
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--tcp", "--tcp-connect", "--udp", "--icmp":
			if mode != "" {
				return errors.New("requires one probe mode")
			}
			mode = arg
		case "--flags", "--data", "-c", "--count", "--rate", "-p", "--dest-port", "-g", "--source-port":
			i++
			if i >= len(args) {
				return errors.New("option needs a value")
			}
			value := args[i]
			if arg == "--flags" {
				if flags != "" {
					return errors.New("duplicate TCP flags")
				}
				flags = strings.ToLower(value)
				continue
			}
			if arg == "--data" {
				if data != "" {
					return errors.New("duplicate payload")
				}
				data = value
				continue
			}
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return errors.New("probe option must be numeric")
			}
			switch arg {
			case "-c", "--count":
				if count != -1 {
					return errors.New("duplicate count")
				}
				count = n
			case "--rate":
				if rate != -1 {
					return errors.New("duplicate rate")
				}
				rate = n
			case "-p", "--dest-port":
				if port != -1 {
					return errors.New("duplicate destination port")
				}
				port = n
			case "-g", "--source-port":
				if sourcePort != -1 {
					return errors.New("duplicate source port")
				}
				sourcePort = n
			}
		default:
			if strings.HasPrefix(arg, "-") || target != "" || net.ParseIP(arg) == nil {
				return errors.New("requires one literal IP target and audited options")
			}
			target = arg
		}
	}
	if mode == "" || target == "" || count < 1 || count > 3 || rate != 1 || sourcePort > 65535 {
		return errors.New("requires one mode, one IP, count 1-3, and rate 1")
	}
	if mode == "--icmp" {
		if port != -1 || sourcePort != -1 || flags != "" || data != "" {
			return errors.New("ICMP probe has no TCP or UDP port")
		}
		return nil
	}
	if port < 1 || port > 65535 || sourcePort < -1 {
		return errors.New("requires one destination port and a valid source port")
	}
	if mode == "--tcp" {
		if data != "" {
			return errors.New("custom payload requires UDP mode")
		}
		switch flags {
		case "syn", "ack", "fin", "fin,psh,urg":
			return nil
		}
		return errors.New("raw TCP probe needs audited flags")
	}
	if flags != "" {
		return errors.New("TCP flags require raw TCP mode")
	}
	if data != "" {
		if mode != "--udp" {
			return errors.New("custom payload requires UDP mode")
		}
		value := strings.TrimPrefix(data, "0x")
		if len(value) == 0 || len(value) > 1024 || len(value)%2 != 0 {
			return errors.New("UDP payload must contain 1-512 hex bytes")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return errors.New("UDP payload must be hexadecimal")
		}
	}
	return nil
}
