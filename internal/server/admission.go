package server

import (
	"errors"
	"net"
	"sync"
)

var (
	ErrAdmissionRejected  = errors.New("unauthenticated connection capacity reached")
	ErrAdmissionInvalidIP = errors.New("connection source address is invalid")
)

type admissionIP struct {
	family byte
	bytes  [16]byte
}

type Admission struct {
	mu       sync.Mutex
	maxTotal int
	maxPerIP int
	total    int
	perIP    map[admissionIP]int
}

func NewAdmission(maxUnauthenticated int, maxPerIP int) *Admission {
	return &Admission{
		maxTotal: maxUnauthenticated,
		maxPerIP: maxPerIP,
		perIP:    make(map[admissionIP]int),
	}
}

func (admission *Admission) Acquire(ip net.IP) (func(), error) {
	key, ok := admissionIPKey(ip)
	if !ok {
		return nil, ErrAdmissionInvalidIP
	}
	admission.mu.Lock()
	if admission.maxTotal <= 0 || admission.maxPerIP <= 0 ||
		admission.total >= admission.maxTotal || admission.perIP[key] >= admission.maxPerIP {
		admission.mu.Unlock()
		return nil, ErrAdmissionRejected
	}
	admission.total++
	admission.perIP[key]++
	admission.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			admission.mu.Lock()
			admission.total--
			admission.perIP[key]--
			if admission.perIP[key] == 0 {
				delete(admission.perIP, key)
			}
			admission.mu.Unlock()
		})
	}, nil
}

func admissionIPKey(ip net.IP) (admissionIP, bool) {
	var key admissionIP
	if ip == nil {
		return key, false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		key.family = 4
		copy(key.bytes[:4], ipv4)
		return key, true
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		key.family = 6
		copy(key.bytes[:], ipv6)
		return key, true
	}
	return key, false
}
