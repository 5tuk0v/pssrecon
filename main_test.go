package main

import (
	"strings"
	"testing"
)

func TestDecodeRegistryString(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr string
	}{
		{name: "terminated", data: []byte{'A', 0, 'B', 0, 'C', 0, 0, 0}, want: "ABC"},
		{name: "unterminated", data: []byte{'A', 0, 'B', 0, 'C', 0}, want: "ABC"},
		{name: "missing", data: nil, wantErr: "invalid UTF-16 data length 0"},
		{name: "odd length", data: []byte{'A'}, wantErr: "invalid UTF-16 data length 1"},
		{name: "empty string", data: []byte{0, 0}, wantErr: "is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRegistryString("SiteServer", tt.data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("decodeRegistryString() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("decodeRegistryString() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestPXERegistryStatus(t *testing.T) {
	dword := func(value uint32) *uint32 { return &value }
	tests := []struct {
		name     string
		isPXE    *uint32
		isActive *uint32
		want     string
	}{
		{"enabled and responding", dword(1), dword(1), "[+] PXE enabled for responses in registry (IsPXE=1, IsActive=1)"},
		{"enabled but not responding", dword(1), dword(0), "[i] PXE support flag set; response flag off (IsPXE=1, IsActive=0)"},
		{"conflicting flags", dword(0), dword(1), "[!] Conflicting PXE registry flags (IsPXE=0, IsActive=1)"},
		{"disabled", dword(0), dword(0), "[i] PXE disabled in registry (IsPXE=0, IsActive=0)"},
		{"both absent", nil, nil, "[i] No PXE registry flags present"},
		{"isPXE absent", nil, dword(0), "[i] No PXE configuration indicated (IsPXE absent, IsActive=0)"},
		{"isPXE absent but active", nil, dword(1), "[!] IsActive set without IsPXE (IsPXE absent, IsActive=1)"},
		{"isActive absent", dword(1), nil, "[!] PXE response flag absent (IsPXE=1, IsActive absent)"},
		{"isActive absent and PXE off", dword(0), nil, "[i] PXE not enabled in registry (IsPXE=0, IsActive absent)"},
		{"unexpected value", dword(2), dword(1), "[!] Unexpected PXE registry values (IsPXE=2, IsActive=1)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pxeRegistryStatus(tt.isPXE, tt.isActive); got != tt.want {
				t.Fatalf("pxeRegistryStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}
