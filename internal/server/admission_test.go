package server

import (
	"errors"
	"net"
	"sync"
	"testing"
)

func TestAdmissionEnforcesTotalAndPerIPCapacity(t *testing.T) {
	admission := NewAdmission(2, 1)
	releaseFirst, err := admission.Acquire(net.ParseIP("192.0.2.10"))
	if err != nil {
		t.Fatalf("Acquire(first): %v", err)
	}
	if _, err := admission.Acquire(net.ParseIP("192.0.2.10")); !errors.Is(err, ErrAdmissionRejected) {
		t.Fatalf("same-IP Acquire() error = %v, want ErrAdmissionRejected", err)
	}
	releaseSecond, err := admission.Acquire(net.ParseIP("198.51.100.10"))
	if err != nil {
		t.Fatalf("Acquire(second IP): %v", err)
	}
	if _, err := admission.Acquire(net.ParseIP("203.0.113.10")); !errors.Is(err, ErrAdmissionRejected) {
		t.Fatalf("over-total Acquire() error = %v, want ErrAdmissionRejected", err)
	}
	releaseFirst()
	releaseSecond()
}

func TestAdmissionRejectsInvalidIPAndCanonicalizesMappedIPv4(t *testing.T) {
	admission := NewAdmission(2, 1)
	for _, ip := range []net.IP{nil, net.IP{1, 2, 3}} {
		if _, err := admission.Acquire(ip); !errors.Is(err, ErrAdmissionInvalidIP) {
			t.Fatalf("Acquire(%v) error = %v, want ErrAdmissionInvalidIP", ip, err)
		}
	}
	release, err := admission.Acquire(net.ParseIP("192.0.2.20"))
	if err != nil {
		t.Fatalf("Acquire(IPv4): %v", err)
	}
	defer release()
	if _, err := admission.Acquire(net.ParseIP("::ffff:192.0.2.20")); !errors.Is(err, ErrAdmissionRejected) {
		t.Fatalf("mapped IPv4 error = %v, want same-IP rejection", err)
	}
}

func TestAdmissionReleaseIsIdempotent(t *testing.T) {
	admission := NewAdmission(1, 1)
	release, err := admission.Acquire(net.ParseIP("192.0.2.30"))
	if err != nil {
		t.Fatalf("Acquire(): %v", err)
	}
	release()
	release()
	secondRelease, err := admission.Acquire(net.ParseIP("192.0.2.30"))
	if err != nil {
		t.Fatalf("Acquire() after double release: %v", err)
	}
	secondRelease()
}

func TestAdmissionConcurrentAcquireRelease(t *testing.T) {
	admission := NewAdmission(16, 4)
	var wait sync.WaitGroup
	for worker := range 128 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ip := net.IPv4(192, 0, 2, byte(worker%32+1))
			release, err := admission.Acquire(ip)
			if err == nil {
				release()
				release()
			} else if !errors.Is(err, ErrAdmissionRejected) {
				t.Errorf("Acquire(): %v", err)
			}
		}()
	}
	wait.Wait()
	if admission.total != 0 || len(admission.perIP) != 0 {
		t.Fatalf("final admission state = total %d, IPs %d", admission.total, len(admission.perIP))
	}
}
