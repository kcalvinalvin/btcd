package main

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

var (
	rpcuserRegexp = regexp.MustCompile("(?m)^rpcuser=.+$")
	rpcpassRegexp = regexp.MustCompile("(?m)^rpcpass=.+$")
)

func TestCreateDefaultConfigFile(t *testing.T) {
	// find out where the sample config lives
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("Failed finding config file path")
	}
	sampleConfigFile := filepath.Join(filepath.Dir(path), "sample-btcd.conf")

	// Setup a temporary directory
	tmpDir := t.TempDir()
	testpath := filepath.Join(tmpDir, "test.conf")

	// copy config file to location of btcd binary
	data, err := os.ReadFile(sampleConfigFile)
	if err != nil {
		t.Fatalf("Failed reading sample config file: %v", err)
	}
	appPath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		t.Fatalf("Failed obtaining app path: %v", err)
	}
	tmpConfigFile := filepath.Join(appPath, "sample-btcd.conf")
	err = os.WriteFile(tmpConfigFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed copying sample config file: %v", err)
	}

	err = createDefaultConfigFile(testpath)

	if err != nil {
		t.Fatalf("Failed to create a default config file: %v", err)
	}

	content, err := os.ReadFile(testpath)
	if err != nil {
		t.Fatalf("Failed to read generated default config file: %v", err)
	}

	if !rpcuserRegexp.Match(content) {
		t.Error("Could not find rpcuser in generated default config file.")
	}

	if !rpcpassRegexp.Match(content) {
		t.Error("Could not find rpcpass in generated default config file.")
	}
}

// equalAddrs reports whether two address slices hold the same values, treating
// a nil and an empty slice as equal.
func equalAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestConfigureElectrum covers the script hash index and electrum server flag
// combinations a user can pass: how --enableelectrum implies --scripthashindex,
// which combinations are rejected, and how the electrum listen addresses are
// defaulted and normalized.
func TestConfigureElectrum(t *testing.T) {
	defElectrum := net.JoinHostPort("", defaultElectrumServerPort)
	defTLS := net.JoinHostPort("", defaultTLSElectrumServerPort)

	tests := []struct {
		name           string
		cfg            config
		wantErr        bool
		wantScriptHash bool
		wantElectrum   []string
		wantTLS        []string
	}{
		{
			name:           "no flags",
			cfg:            config{},
			wantScriptHash: false,
			wantElectrum:   []string{},
			wantTLS:        []string{},
		},
		{
			name:           "scripthashindex only",
			cfg:            config{ScriptHashIndex: true},
			wantScriptHash: true,
			wantElectrum:   []string{},
			wantTLS:        []string{},
		},
		{
			name:           "dropscripthashindex only",
			cfg:            config{DropScriptHashIndex: true},
			wantScriptHash: false,
			wantElectrum:   []string{},
			wantTLS:        []string{},
		},
		{
			name:    "scripthashindex with dropscripthashindex conflicts",
			cfg:     config{ScriptHashIndex: true, DropScriptHashIndex: true},
			wantErr: true,
		},
		{
			name:    "enableelectrum with dropscripthashindex conflicts",
			cfg:     config{EnableElectrum: true, DropScriptHashIndex: true},
			wantErr: true,
		},
		{
			name:           "enableelectrum implies scripthashindex and default listeners",
			cfg:            config{EnableElectrum: true},
			wantScriptHash: true,
			wantElectrum:   []string{defElectrum},
			wantTLS:        []string{defTLS},
		},
		{
			name: "enableelectrum keeps custom electrum listeners",
			cfg: config{
				EnableElectrum:    true,
				ElectrumListeners: []string{"1.2.3.4:5000"},
			},
			wantScriptHash: true,
			wantElectrum:   []string{"1.2.3.4:5000"},
			wantTLS:        []string{defTLS},
		},
		{
			name: "enableelectrum keeps custom tls listeners",
			cfg: config{
				EnableElectrum:       true,
				TLSElectrumListeners: []string{"1.2.3.4:6000"},
			},
			wantScriptHash: true,
			wantElectrum:   []string{defElectrum},
			wantTLS:        []string{"1.2.3.4:6000"},
		},
		{
			name: "listener without a port gets the default port",
			cfg: config{
				EnableElectrum:    true,
				ElectrumListeners: []string{"1.2.3.4"},
			},
			wantScriptHash: true,
			wantElectrum:   []string{"1.2.3.4:" + defaultElectrumServerPort},
			wantTLS:        []string{defTLS},
		},
		{
			name: "electrum listeners without enableelectrum stay off but normalize",
			cfg: config{
				ElectrumListeners: []string{"1.2.3.4"},
			},
			wantScriptHash: false,
			wantElectrum:   []string{"1.2.3.4:" + defaultElectrumServerPort},
			wantTLS:        []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := test.cfg
			err := cfg.configureElectrum()
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg.ScriptHashIndex != test.wantScriptHash {
				t.Errorf("ScriptHashIndex = %v, want %v",
					cfg.ScriptHashIndex, test.wantScriptHash)
			}
			if !equalAddrs(cfg.ElectrumListeners, test.wantElectrum) {
				t.Errorf("ElectrumListeners = %v, want %v",
					cfg.ElectrumListeners, test.wantElectrum)
			}
			if !equalAddrs(cfg.TLSElectrumListeners, test.wantTLS) {
				t.Errorf("TLSElectrumListeners = %v, want %v",
					cfg.TLSElectrumListeners, test.wantTLS)
			}
		})
	}
}
