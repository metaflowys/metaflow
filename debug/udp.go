package debug

import (
	"bytes"
	"encoding/gob"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
)

type ModuleId uint16
type ModuleOperate uint16

type RegisterCommmandLine func() *cobra.Command
type CommandLineProcess interface {
	RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer)
}

const (
	DEFAULT_LISTEN_PORT    = 9528
	UDP_MAXLEN             = 1500
	DEBUG_MESSAGE_ARGS_LEN = 1200
	MODULE_MAX             = 32
)

var (
	hostIp       = "0.0.0.0"
	hostPort int = DEFAULT_LISTEN_PORT
	running      = false
	log          = logging.MustGetLogger(os.Args[0])

	recvHandlers     = [MODULE_MAX]CommandLineProcess{}
	registerHandlers = [MODULE_MAX]RegisterCommmandLine{}
)

type DebugMessage struct {
	Module, Operate uint16
	Result          uint32
	Args            [DEBUG_MESSAGE_ARGS_LEN]byte
}

func SetIpAndPort(ip string, port int) {
	hostIp = ip
	hostPort = port
}

func RecvFromServer(conn *net.UDPConn) (*bytes.Buffer, error) {
	data := make([]byte, UDP_MAXLEN)
	msg := DebugMessage{}

	if _, _, err := conn.ReadFrom(data); err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&msg); err != nil {
		return nil, err
	} else if msg.Result != 0 {
		return nil, errors.New("msg.Result != 0")
	}
	return bytes.NewBuffer(msg.Args[:]), nil
}

func SendToServer(module ModuleId, operate ModuleOperate, args *bytes.Buffer) (*net.UDPConn, *bytes.Buffer, error) {
	conn, err := net.Dial("udp4", hostIp+":"+strconv.Itoa(hostPort))
	if err != nil {
		return nil, nil, err
	}
	sendBuffer := bytes.Buffer{}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg := DebugMessage{Module: uint16(module), Operate: uint16(operate), Result: 0}
	if args != nil {
		args.Read(msg.Args[:])
	}
	encoder := gob.NewEncoder(&sendBuffer)
	if err := encoder.Encode(msg); err != nil {
		return conn.(*net.UDPConn), nil, err
	}

	conn.Write(sendBuffer.Bytes())
	recv, err := RecvFromServer(conn.(*net.UDPConn))
	return conn.(*net.UDPConn), recv, err
}

func SendToClient(conn *net.UDPConn, remote *net.UDPAddr, result uint32, args *bytes.Buffer) {
	if args != nil && args.Len() > DEBUG_MESSAGE_ARGS_LEN {
		log.Warningf("len(args) > %v", DEBUG_MESSAGE_ARGS_LEN)
		return
	}
	buffer := bytes.Buffer{}
	msg := DebugMessage{Module: 0, Result: result, Operate: 11}
	if args != nil {
		args.Read(msg.Args[:])
	}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(msg); err != nil {
		log.Error(err)
		return
	}

	if buffer.Len() > UDP_MAXLEN {
		log.Warningf("buffer.Len() > %v", UDP_MAXLEN)
		return
	}
	conn.WriteToUDP(buffer.Bytes(), remote)
	return
}

func process(conn *net.UDPConn) {
	data := make([]byte, UDP_MAXLEN)
	msg := DebugMessage{}

	_, remote, err := conn.ReadFromUDP(data)
	if err != nil {
		return
	}
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&msg); err != nil {
		log.Error(err)
		return
	}
	if recvHandlers[msg.Module] != nil {
		recvHandlers[msg.Module].RecvCommand(conn, remote, msg.Operate, bytes.NewBuffer(msg.Args[:]))
	}
}

func debugListener() {
	go func() {
		addr := &net.UDPAddr{IP: net.ParseIP(hostIp), Port: hostPort}
		listener, err := net.ListenUDP("udp4", addr)
		if err != nil {
			log.Error(err)
			return
		}
		defer listener.Close()
		log.Infof("DebugListener <%v:%v>", hostIp, hostPort)
		for {
			process(listener)
		}
	}()
}

func Register(module ModuleId, process CommandLineProcess) {
	recvHandlers[module] = process
	if running == false {
		debugListener()
		running = true
	}
}

func RegisterCommand(module ModuleId, cmd RegisterCommmandLine) {
	registerHandlers[module] = cmd
}

func GenerateCommand() []*cobra.Command {
	commands := make([]*cobra.Command, 0, len(registerHandlers))
	for _, handler := range registerHandlers {
		if handler != nil {
			command := handler()
			commands = append(commands, command)
		}
	}
	return commands
}
