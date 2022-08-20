package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	StartChar byte = 0xFE
	EndChar   byte = 0xEF

	ActionRead  byte = 0x1
	ActionWrite byte = 0x2
	ActionError byte = 0x4
)

func PackNet(no byte, action byte, data []byte, ip uint32, port uint16) []byte {
	// startChar 1+ action 1+ packNo 1+ src ip 4+src port 2 + data len 2 +xx+2+1
	l := len(data)
	// 1+1+1+4+2+2+x+2+1+1
	buf := make([]byte, 14+l)
	inx := 0
	buf[inx] = StartChar
	inx++
	st := inx
	// 动作
	buf[inx] = action
	inx++
	buf[inx] = no
	inx++
	// src ip
	WriteUInt32BE(ip, buf, inx)
	inx += 4
	// src port
	WriteUInt16BE(int(port), buf, inx)
	inx += 2
	WriteUInt16BE(l, buf, inx)
	inx += 2
	Cp(data, 0, buf, inx, l)
	inx += l
	WriteUInt16LE(int(Crc16(buf, st, 10+l)), buf, inx)
	inx += 2
	buf[inx] = EndChar
	return buf
}

type TargetPack struct {
	PackNo byte
	Action byte
	Src    uint32
	Port   uint16
	Data   []byte
}

func BuildTargetPack(packNo byte, action byte, src uint32, port uint16, data []byte) *TargetPack {
	t := new(TargetPack)
	t.PackNo = packNo
	t.Action = action
	t.Src = src
	t.Port = port
	t.Data = cloneBytes(data)
	return t
}

func (p *TargetPack) NetAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", byte(p.Src>>24), byte(p.Src>>16), byte(p.Src>>8), byte(p.Src&0xff), p.Port)
}

func (p *TargetPack) Match(ip uint32, port uint16) bool {
	return p.Src == ip && p.Port == port
}

func (p *TargetPack) ToBytes() []byte {
	return PackNet(p.PackNo, p.Action, p.Data, p.Src, p.Port)
}

const SizeBuf = 64 * 1024

type ProcessRequest struct {
	Buf        []byte
	WriteIndex int
}

func BuildProcessRequest() *ProcessRequest {
	v := new(ProcessRequest)
	v.Buf = make([]byte, SizeBuf)
	v.WriteIndex = 0
	return v
}

func (p *ProcessRequest) Put(b []byte) {
	dLen := len(b)
	if dLen == 0 {
		return
	}
	if p.WriteIndex+dLen > SizeBuf {
		p.WriteIndex = 0
		return
	}
	p.WriteIndex += Cp(b, 0, p.Buf, p.WriteIndex, len(b))
}

func (p *ProcessRequest) Parse() *TargetPack {
	return UnpackNet(p.Buf, &p.WriteIndex)
}

func UnpackNet(buf []byte, writeIndex *int) *TargetPack {
	l := *writeIndex
	if l <= 0 {
		return nil
	}
	startIndex := bytes.IndexByte(buf, StartChar)
	if startIndex < 0 {
		if *writeIndex > 0 {
			*writeIndex = 0
		}
		return nil
	}
	// startChar 1 + action 1 + packNo 1+ src Ip 4 + src port 2+ data len 2
	hLen := 1 + 1 + 1 + 4 + 2
	dLen := *writeIndex - startIndex
	if dLen < hLen {
		if startIndex > 0 {
			*writeIndex = Cp(buf, startIndex, buf, 0, dLen)
		}
		return nil
	}
	// 1 2 3 4 5 6
	// *
	dataLenPointer := startIndex + hLen
	dataPointerData := dataLenPointer + 2
	realDataLen := ReadUInt16BE(buf, dataLenPointer)
	crcPointer := dataPointerData + realDataLen
	tailPointer := crcPointer + 3
	if tailPointer > *writeIndex {
		if startIndex > 0 {
			*writeIndex = Cp(buf, startIndex, buf, 0, dLen)
		}
		return nil
	}
	oriCrc := ReadUInt16LE(buf, crcPointer)
	calCrc := Crc16(buf, startIndex+1, realDataLen+10)
	if oriCrc == int(calCrc) {
		ret := new(TargetPack)
		ret.Action = buf[startIndex+1]
		ret.PackNo = buf[startIndex+2]
		ret.Src = ReadUInt32BE(buf[startIndex+3:])
		ret.Port = uint16(ReadUInt16BE(buf, startIndex+7))
		ret.Data = cloneBytes(buf[dataPointerData : dataPointerData+realDataLen])
		*writeIndex = Cp(buf, tailPointer, buf, 0, *writeIndex-tailPointer)
		return ret
	} else {
		*writeIndex = Cp(buf, startIndex+1, buf, 0, *writeIndex-startIndex-1)
	}
	return nil
}

func cloneBytes(b []byte) []byte {
	x := make([]byte, len(b))
	Cp(b, 0, x, 0, len(b))
	return x
}

type QueueNode struct {
	Data *TargetPack
	Next *QueueNode
}

func BuildQueueNode(p *TargetPack) *QueueNode {
	t := new(QueueNode)
	t.Data = p
	return t
}

type MessageQueue struct {
	Queue   *QueueNode
	Locker  *sync.Mutex
	Counter byte
}

func BuildQueue() *MessageQueue {
	r := new(MessageQueue)
	r.Counter = 0
	r.Locker = new(sync.Mutex)
	r.Queue = nil
	return r
}

func (p *MessageQueue) Product(n *QueueNode) {

	p.Locker.Lock()
	defer p.Locker.Unlock()
	if p.Queue == nil {
		p.Queue = n
		p.Counter++
		n.Data.PackNo = p.Counter
		n.Next = nil
		return
	}
	f := p.Queue
	for {
		if f.Next == nil {
			f.Next = n
			p.Counter++
			n.Data.PackNo = p.Counter
			n.Next = nil
			break
		}
		f = f.Next
	}
}

func (p *MessageQueue) Clean() {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	f := p.Queue
	for {
		if f == nil {
			break
		}
		f = f.Next
	}
}

func (p *MessageQueue) TryRouteClient(conn net.Conn) (*QueueNode, error) {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	if p.Queue == nil {
		return nil, nil
	}
	ip, port := ToAddr(conn.RemoteAddr().String())
	f := p.Queue
	for {
		if f.Data.Match(ip, port) {
			break
		}
		f = f.Next
		if f == nil {
			return nil, nil
		}
	}
	p.Queue = f.Next
	_, e := conn.Write(f.Data.Data)
	if e != nil {
		return nil, e
	}
	return f, nil
}

func (p *MessageQueue) TryRouteClientByKey(key string, conn net.Conn) (*QueueNode, error) {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	if p.Queue == nil {
		return nil, nil
	}

	f := p.Queue
	for {
		if strings.Compare(f.Data.NetAddr(), key) == 0 {
			break
		}
		f = f.Next
		if f == nil {
			return nil, nil
		}
	}
	p.Queue = f.Next
	_, e := conn.Write(f.Data.Data)
	if e != nil {
		return nil, e
	}
	return f, nil
}

func (p *MessageQueue) Consumer(conn net.Conn) (*QueueNode, error) {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	if p.Queue == nil {
		return nil, nil
	}
	f := p.Queue
	p.Queue = f.Next
	_, e := conn.Write(f.Data.ToBytes())
	if e != nil {
		return nil, e
	}
	return f, nil
}

type RWQueue struct {
	Reader *MessageQueue
	Writer *MessageQueue
}

func BuildRWQueue() *RWQueue {
	t := new(RWQueue)
	t.Reader = BuildQueue()
	t.Writer = BuildQueue()
	return t
}

type Router struct {
	QueueList *RWQueue
	Locker    *sync.Mutex
	HasLinker bool
}

func BuildRouter() *Router {
	t := new(Router)
	t.QueueList = BuildRWQueue()
	t.Locker = new(sync.Mutex)
	t.HasLinker = false
	return t
}

func (p *Router) UpdateLinker(b bool) {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	p.HasLinker = b
}

func (p *Router) GetLinker() bool {
	p.Locker.Lock()
	defer p.Locker.Unlock()
	return p.HasLinker
}

var GlobalRouter = BuildRouter()

func ProxyServer(proxyServiceAddress string) {
	l, e := net.Listen("tcp", proxyServiceAddress)
	if e != nil {
		log.Default().Println(e)
		return
	}
	log.Println("::: listen at ", proxyServiceAddress)
	for {
		conn, e := l.Accept()
		if e != nil {
			log.Println(e)
			continue
		}
		GlobalRouter.QueueList.Writer.Clean()
		GlobalRouter.QueueList.Reader.Clean()
		GlobalRouter.UpdateLinker(true)
		log.Println(conn.RemoteAddr().String())
		go func(cc net.Conn) {
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				GlobalRouter.UpdateLinker(false)
				GlobalRouter.QueueList.Writer.Clean()
				GlobalRouter.QueueList.Reader.Clean()
				cancel()
				conn.Close()
			}()
			go func(ctx2 context.Context) {

				buf := make([]byte, SizeBuf)
				processor := BuildProcessRequest()
				for {
					select {
					case <-ctx2.Done():
						return
					default:
						reader := bufio.NewReader(conn)
						n, e := reader.Read(buf)
						if e != nil {
							cancel()
							return
						}
						processor.Put(buf[:n])
						for {
							r := processor.Parse()
							if r != nil {
								GlobalRouter.QueueList.Reader.Product(BuildQueueNode(r))
							} else {
								break
							}
						}
					}
				}
			}(ctx)
			go func(ctx2 context.Context) {
				for {
					select {
					case <-ctx2.Done():
						return
					default:
						_, e := GlobalRouter.QueueList.Writer.Consumer(conn)
						if e != nil {
							GlobalRouter.QueueList.Writer.Clean()
							GlobalRouter.QueueList.Reader.Clean()
							cancel()
							return
						}
					}
				}
			}(ctx)
			select {
			case <-ctx.Done():
			}
		}(conn)

	}

}

func ToAddr(str string) (uint32, uint16) {
	d, _ := netip.ParseAddrPort(str)
	return ReadUInt32BE(d.Addr().AsSlice()), d.Port()
}

func InProxyServer(inboundAddress string) {
	l, e := net.Listen("tcp", inboundAddress)
	if e != nil {
		log.Default().Println(e)
		return
	}
	log.Println("::: device inbound listen @ ", inboundAddress)
	for {
		conn, e := l.Accept()
		if e != nil {
			log.Println(e)
			continue
		}
		log.Println("::: (S) <<-- ", conn.RemoteAddr().String())
		go func(cc net.Conn) {
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				conn.Close()
				if GlobalRouter.GetLinker() {
					ip, port := ToAddr(conn.RemoteAddr().String())
					GlobalRouter.QueueList.Writer.Product(BuildQueueNode(BuildTargetPack(0, ActionError, ip, port, []byte{})))
				}
			}()
			go func(ctx2 context.Context) {
				buf := make([]byte, SizeBuf)
				for {
					select {
					case <-ctx2.Done():
						return
					default:
						reader := bufio.NewReader(conn)
						n, e := reader.Read(buf)
						if e != nil {
							cancel()
							return
						}
						log.Println("::: ", conn.RemoteAddr().String(), " -->> ")
						println(hex.Dump(buf[:n]))
						if GlobalRouter.GetLinker() {
							ip, port := ToAddr(conn.RemoteAddr().String())
							GlobalRouter.QueueList.Writer.Product(BuildQueueNode(BuildTargetPack(0, ActionRead, ip, port, cloneBytes(buf[:n]))))
						} else {
							log.Println("::: ", conn.RemoteAddr().String(), " -->> ")
							println(hex.Dump(buf[:n]))
						}
					}
				}
			}(ctx)
			go func(ctx2 context.Context) {
				//writer
				for {
					select {
					case <-ctx2.Done():
						return
					default:
						if GlobalRouter.GetLinker() {
							d, e := GlobalRouter.QueueList.Reader.TryRouteClient(conn)
							if e != nil {
								cancel()
								return
							}
							if d != nil {
								log.Println("::: ", conn.RemoteAddr().String(), " <<-- ")
								println(hex.Dump(d.Data.Data))
							}
						}
					}
				}
			}(ctx)
			select {
			case <-ctx.Done():
				println("::: main exit .")
			}
		}(conn)

	}
}

type TargetConnect struct {
	Conn      map[string]*net.Conn
	connMutex *sync.Mutex
}

func BuildTargetConnect() *TargetConnect {
	t := new(TargetConnect)
	t.connMutex = new(sync.Mutex)
	t.Conn = make(map[string]*net.Conn)
	return t
}

func (p *TargetConnect) NewConnect(target string, targetPack *TargetPack) (*net.Conn, error) {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()
	t := p.Conn[targetPack.NetAddr()]
	if t != nil {
		return nil, nil
	}
	c := NewConnect(target)
	if c == nil {
		return nil, errors.New("connect fail")
	}
	p.Conn[targetPack.NetAddr()] = c
	return c, nil
}

func (p *TargetConnect) Reg(key string, conn *net.Conn) {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()
	p.Conn[key] = conn
}

func (p *TargetConnect) UnReg(key string) *net.Conn {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()
	r := p.Conn[key]
	delete(p.Conn, key)
	return r
}

func (p *TargetConnect) Clean() {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()
	for k, v := range p.Conn {
		(*v).Close()
		delete(p.Conn, k)
	}
}

func (p *TargetConnect) Has(key string) bool {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()
	return p.Conn[key] != nil
}

func NewConnect(addr string) *net.Conn {
	conn, e := net.Dial("tcp", addr)
	if e != nil {
		log.Print(e)
		return nil
	}
	return &conn
}

func tryConnectTarget(remoteAddress string, conn net.Conn, key string) {
	go func(remote string, cn net.Conn) {
		ct1, cancel := context.WithCancel(context.Background())
		defer func() {
			GlobalClientConnect.UnReg(key)
			cancel()
			cn.Close()
		}()
		go func() {
			buf := make([]byte, SizeBuf)
			for {
				select {
				case <-ct1.Done():
					return
				default:
					reader := bufio.NewReader(cn)
					n, e := reader.Read(buf)
					if e != nil {
						cancel()
						return
					}
					if n == 0 {
						continue
					}
					ip, port := ToAddr(remote)
					log.Println("::: <<-- ", conn.RemoteAddr().String())
					println(hex.Dump(buf[:n]))
					if GlobalClientRouter.GetLinker() {
						GlobalClientRouter.QueueList.Reader.Product(BuildQueueNode(BuildTargetPack(0, ActionWrite, ip, port, buf[:n])))
					}
				}
			}
		}()
		go func(cn net.Conn) {
			for {
				select {
				case <-ct1.Done():
					return
				default:
					if GlobalClientRouter.GetLinker() {

						b, e := GlobalClientRouter.QueueList.Writer.TryRouteClientByKey(remote, cn)
						if e != nil {
							cancel()
							return
						}
						if b == nil {
							time.Sleep(1e7)
						} else {
							log.Println("::: -->> ", conn.RemoteAddr().String())
							println(hex.Dump(b.Data.Data))
						}
					} else {
						time.Sleep(1e7)
					}
				}
			}
		}(conn)
		select {
		case <-ct1.Done():
		}
		log.Println("::: <<-->> (X) ", conn.RemoteAddr().String())
	}(remoteAddress, conn)
}

var GlobalClientRouter = BuildRouter()
var GlobalClientConnect = BuildTargetConnect()

func OutLocal(target string, remote string) {
	addr := remote
	for {
		conn, e := net.Dial("tcp", addr)
		if e != nil {
			log.Printf("::: connect %s fail ", addr)
			time.Sleep(5e9)
			continue
		}
		log.Printf("::: connect %s success ", addr)
		GlobalClientRouter.QueueList.Writer.Clean()
		GlobalClientRouter.QueueList.Reader.Clean()
		GlobalClientRouter.UpdateLinker(true)
		ch := make(chan int, 1)
		proc := BuildProcessRequest()
		go func() {
			ct1, cancel := context.WithCancel(context.Background())
			defer func() {
				ch <- 1
				GlobalClientRouter.UpdateLinker(false)
				GlobalClientRouter.QueueList.Writer.Clean()
				GlobalClientRouter.QueueList.Reader.Clean()
				cancel()
				conn.Close()
				GlobalClientConnect.Clean()
			}()
			go func() {
				buf := make([]byte, SizeBuf)
				for {
					select {
					case <-ct1.Done():
						return
					default:
						reader := bufio.NewReader(conn)
						n, e := reader.Read(buf)
						if e != nil {
							cancel()
							return
						}
						proc.Put(buf[:n])
						for {
							r := proc.Parse()
							if r == nil {
								break
							}
							if r.Action == ActionError {
								cli := GlobalClientConnect.UnReg(r.NetAddr())
								if cli != nil {
									(*cli).Close()
								}
								continue

							}
							c, e := GlobalClientConnect.NewConnect(target, r)
							if e != nil {
								break
							}
							if c != nil {
								tryConnectTarget(r.NetAddr(), *c, r.NetAddr())
							}
							if GlobalClientRouter.GetLinker() {
								GlobalClientRouter.QueueList.Writer.Product(BuildQueueNode(r))
							}
						}
					}
				}
			}()

			go func() {
				for {
					select {
					case <-ct1.Done():
						return
					default:
						d, e := GlobalClientRouter.QueueList.Reader.Consumer(conn)
						if e != nil {
							cancel()
							return
						}

						if d == nil {
							time.Sleep(1e7)
						}
					}
				}
			}()
			select {
			case <-ct1.Done():

			}
		}()
		select {
		case <-ch:
		}
	}
	log.Println("::: (X)<<-->>(X) ")

}
