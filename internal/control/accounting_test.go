package control

import "testing"

// The rows are what a real finished allocation looks like: the job row carries
// what was asked for, .batch carries what the workload used, and .extern carries
// almost nothing, which is exactly why it must not be read as the usage.
const sacctRows = `12345|4|8192000K|3600|14400|||
12345.batch|4|8192000K|3600|14400|4096000K|02:00:00
12345.extern|4|8192000K|3600|14400|4K|00:00:00`

func TestParseSacctUtilReadsUsageFromTheBatchStep(t *testing.T) {
	stats := parseSacctUtil(sacctRows)
	if stats.Cores != 4 || stats.ElapsedSeconds != 3600 {
		t.Fatalf("allocation figures came from the wrong row: %+v", stats)
	}
	if stats.RequestedMemory != "7.8 GB" || stats.MaxRSS != "3.9 GB" {
		t.Fatalf("memory was not read in KiB from the right rows: %+v", stats)
	}
	// TotalCPU 02:00:00 = 7200s of the 14400 CPU-seconds allocated.
	if stats.CPUEfficiencyPct < 49.9 || stats.CPUEfficiencyPct > 50.1 {
		t.Fatalf("CPU efficiency = %v, want ~50", stats.CPUEfficiencyPct)
	}
	if stats.MemoryEfficiencyPct < 49.9 || stats.MemoryEfficiencyPct > 50.1 {
		t.Fatalf("memory efficiency = %v, want ~50", stats.MemoryEfficiencyPct)
	}
	if !stats.Complete() {
		t.Fatal("a row carrying a peak reads as incomplete")
	}
}

// slurmdbd flushes step usage a beat after the job ends, so the read that lands
// first legitimately has no peak and no consumed CPU. A zero TotalCPU is that
// state, not an idle job, and reporting 0% efficiency for it would be a lie.
func TestParseSacctUtilTreatsAnUnflushedRowAsIncomplete(t *testing.T) {
	stats := parseSacctUtil("12345|4|8192000K|3600|14400||\n12345.batch|4|8192000K|3600|14400||00:00:00")
	if stats.Complete() {
		t.Fatalf("an unflushed row reads as a finished report: %+v", stats)
	}
	if stats.CPUEfficiencyPct != 0 || stats.MaxRSS != "" {
		t.Fatalf("an unflushed row invented figures: %+v", stats)
	}
	if stats.Cores != 4 || stats.ElapsedSeconds != 3600 {
		t.Fatalf("what the allocation asked for is known regardless: %+v", stats)
	}
}

func TestParseSacctUtilAnswersNothingForNothing(t *testing.T) {
	if stats := parseSacctUtil("\n  \n"); stats != (RunStats{}) {
		t.Fatalf("empty accounting produced %+v", stats)
	}
}

func TestHMSSecondsReadsSlurmDurations(t *testing.T) {
	for text, want := range map[string]float64{
		"02:00:00":   7200,
		"1-00:00:00": 86400,
		"05:30":      330,
		"":           0,
		"not-a-time": 0,
		"00:00:00":   0,
	} {
		if got := hmsSeconds(text); got != want {
			t.Errorf("hmsSeconds(%q) = %v, want %v", text, got, want)
		}
	}
}
