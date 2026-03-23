// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
)

func TestPrintMapList(t *testing.T) {
	tests := []struct {
		name     string
		maps     []*models.BPFMap
		expected []string
	}{
		{
			name: "map with cache entries shows count",
			maps: []*models.BPFMap{
				{
					Path: "/sys/fs/bpf/tc/globals/cilium_ipcache",
					Cache: []*models.BPFMapEntry{
						{Key: "key1", Value: "val1"},
						{Key: "key2", Value: "val2"},
					},
				},
			},
			expected: []string{"cilium_ipcache", "2", "0", "true"},
		},
		{
			name: "map with nil cache shows unknown",
			maps: []*models.BPFMap{
				{
					Path: "/sys/fs/bpf/tc/globals/cilium_node_map_v2",
				},
			},
			expected: []string{"cilium_node_map_v2", "unknown", "0", "false"},
		},
		{
			name: "map with empty cache shows zero",
			maps: []*models.BPFMap{
				{
					Path:  "/sys/fs/bpf/tc/globals/cilium_empty_map",
					Cache: []*models.BPFMapEntry{},
				},
			},
			expected: []string{"cilium_empty_map", "0", "0", "true"},
		},
		{
			name: "map with cache errors counts them",
			maps: []*models.BPFMap{
				{
					Path: "/sys/fs/bpf/tc/globals/cilium_test",
					Cache: []*models.BPFMapEntry{
						{Key: "key1", Value: "val1"},
						{Key: "key2", Value: "val2", LastError: "sync failed"},
					},
				},
			},
			expected: []string{"cilium_test", "2", "1", "true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			printMapList(&models.BPFMapList{Maps: tt.maps})

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			for _, exp := range tt.expected {
				if !strings.Contains(output, exp) {
					t.Errorf("expected output to contain %q, got:\n%s", exp, output)
				}
			}
		})
	}
}
