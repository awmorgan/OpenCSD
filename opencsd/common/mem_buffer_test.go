package common

import (
	"testing"
)

func TestMemoryBuffer_ReadMemory(t *testing.T) {
	// Create a simple memory buffer
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	mb := NewMemoryBuffer(0x1000, data)

	tests := []struct {
		name      string
		addr      uint64
		size      int
		wantBytes []byte
		wantN     int
		wantErr   bool
	}{
		{
			name:      "read from start",
			addr:      0x1000,
			size:      4,
			wantBytes: []byte{0x01, 0x02, 0x03, 0x04},
			wantN:     4,
			wantErr:   false,
		},
		{
			name:      "read from middle",
			addr:      0x1003,
			size:      3,
			wantBytes: []byte{0x04, 0x05, 0x06},
			wantN:     3,
			wantErr:   false,
		},
		{
			name:      "read to end",
			addr:      0x1006,
			size:      2,
			wantBytes: []byte{0x07, 0x08},
			wantN:     2,
			wantErr:   false,
		},
		{
			name:      "partial read beyond end",
			addr:      0x1007,
			size:      4,
			wantBytes: []byte{0x08, 0x00, 0x00, 0x00}, // Only first byte is valid
			wantN:     1,
			wantErr:   false,
		},
		{
			name:    "read before buffer",
			addr:    0x0FFF,
			size:    4,
			wantN:   0,
			wantErr: true,
		},
		{
			name:    "read after buffer",
			addr:    0x1008,
			size:    4,
			wantN:   0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.size)
			n, err := mb.ReadMemory(tt.addr, buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadMemory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if n != tt.wantN {
				t.Errorf("ReadMemory() n = %d, want %d", n, tt.wantN)
			}

			if tt.wantBytes != nil {
				for i := 0; i < tt.wantN; i++ {
					if buf[i] != tt.wantBytes[i] {
						t.Errorf("ReadMemory() buf[%d] = 0x%02X, want 0x%02X", i, buf[i], tt.wantBytes[i])
					}
				}
			}
		})
	}
}

func TestMemoryBuffer_Contains(t *testing.T) {
	data := make([]byte, 0x100)
	mb := NewMemoryBuffer(0x80000000, data)

	tests := []struct {
		name string
		addr uint64
		want bool
	}{
		{"start address", 0x80000000, true},
		{"middle address", 0x80000050, true},
		{"last valid address", 0x800000FF, true},
		{"beyond end", 0x80000100, false},
		{"before start", 0x7FFFFFFF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mb.Contains(tt.addr); got != tt.want {
				t.Errorf("Contains(0x%X) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestMemoryBuffer_EndAddr(t *testing.T) {
	data := make([]byte, 0x1000)
	mb := NewMemoryBuffer(0x80000000, data)

	want := uint64(0x80001000)
	if got := mb.EndAddr(); got != want {
		t.Errorf("EndAddr() = 0x%X, want 0x%X", got, want)
	}
}

func TestMultiRegionMemory_ReadMemory(t *testing.T) {
	mrm := NewMultiRegionMemory()

	// Add three regions with gaps
	region1 := NewMemoryBuffer(0x1000, []byte{0x11, 0x12, 0x13, 0x14})
	region2 := NewMemoryBuffer(0x2000, []byte{0x21, 0x22, 0x23, 0x24})
	region3 := NewMemoryBuffer(0x3000, []byte{0x31, 0x32, 0x33, 0x34})

	mrm.AddRegion(region1)
	mrm.AddRegion(region2)
	mrm.AddRegion(region3)

	tests := []struct {
		name      string
		addr      uint64
		size      int
		wantBytes []byte
		wantN     int
		wantErr   bool
	}{
		{
			name:      "read from region1",
			addr:      0x1001,
			size:      2,
			wantBytes: []byte{0x12, 0x13},
			wantN:     2,
			wantErr:   false,
		},
		{
			name:      "read from region2",
			addr:      0x2002,
			size:      2,
			wantBytes: []byte{0x23, 0x24},
			wantN:     2,
			wantErr:   false,
		},
		{
			name:      "read from region3",
			addr:      0x3000,
			size:      4,
			wantBytes: []byte{0x31, 0x32, 0x33, 0x34},
			wantN:     4,
			wantErr:   false,
		},
		{
			name:    "read from gap between regions",
			addr:    0x1500,
			size:    4,
			wantN:   0,
			wantErr: true,
		},
		{
			name:    "read from unmapped region",
			addr:    0x0000,
			size:    4,
			wantN:   0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.size)
			n, err := mrm.ReadMemory(tt.addr, buf)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadMemory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if n != tt.wantN {
				t.Errorf("ReadMemory() n = %d, want %d", n, tt.wantN)
			}

			if tt.wantBytes != nil {
				for i := 0; i < tt.wantN; i++ {
					if buf[i] != tt.wantBytes[i] {
						t.Errorf("ReadMemory() buf[%d] = 0x%02X, want 0x%02X", i, buf[i], tt.wantBytes[i])
					}
				}
			}
		})
	}
}

func TestMultiRegionMemory_ARM_Scenario(t *testing.T) {
	// Simulate ARM memory map with VECTORS, CODE, and DATA
	mrm := NewMultiRegionMemory()

	vectors := []byte{0xEA, 0x00, 0x00, 0x0E} // B instruction
	code := []byte{0xE3, 0xA0, 0x00, 0x00}    // MOV r0, #0
	data := []byte{0x12, 0x34, 0x56, 0x78}    // Some data

	mrm.AddRegion(NewMemoryBuffer(0x80000000, vectors))
	mrm.AddRegion(NewMemoryBuffer(0x80000278, code))
	mrm.AddRegion(NewMemoryBuffer(0x80001C28, data))

	// Read instruction from vectors
	buf := make([]byte, 4)
	n, err := mrm.ReadMemory(0x80000000, buf)
	if err != nil {
		t.Fatalf("Failed to read vectors: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes, got %d", n)
	}
	t.Logf("Read from VECTORS (0x80000000): %02X %02X %02X %02X", buf[0], buf[1], buf[2], buf[3])

	// Read instruction from code
	n, err = mrm.ReadMemory(0x80000278, buf)
	if err != nil {
		t.Fatalf("Failed to read code: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes, got %d", n)
	}
	t.Logf("Read from CODE (0x80000278): %02X %02X %02X %02X", buf[0], buf[1], buf[2], buf[3])

	// Read data
	n, err = mrm.ReadMemory(0x80001C28, buf)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes, got %d", n)
	}
	t.Logf("Read from DATA (0x80001C28): %02X %02X %02X %02X", buf[0], buf[1], buf[2], buf[3])
}
