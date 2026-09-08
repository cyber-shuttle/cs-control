package control

import (
	"fmt"
	"strconv"
	"strings"
)

// sacctUtilFormat is what a finished run is measured by. --units=K puts every
// memory field in KiB, so a value is its leading number; ElapsedRaw and
// CPUTimeRAW are already seconds, and TotalCPU is the one duration that is not.
const sacctUtilFormat = "JobID,AllocCPUs,ReqMem,ElapsedRaw,CPUTimeRAW,MaxRSS,TotalCPU"

// RunStats is what Slurm's accounting says one finished allocation used. Every
// figure is optional: slurmdbd flushes step usage a beat after the job ends, so
// an early read legitimately has no peak yet.
type RunStats struct {
	Cores               int     `json:"cores,omitempty"`
	RequestedMemory     string  `json:"requestedMemory,omitempty"`
	ElapsedSeconds      int64   `json:"elapsedSeconds,omitempty"`
	MaxRSS              string  `json:"maxRss,omitempty"`
	CPUEfficiencyPct    float64 `json:"cpuEfficiencyPct,omitempty"`
	MemoryEfficiencyPct float64 `json:"memoryEfficiencyPct,omitempty"`
}

// Complete reports whether the accounting flush has landed, which is what makes
// a report worth freezing rather than reading again.
func (s RunStats) Complete() bool { return s.MaxRSS != "" }

// parseSacctUtil reads `sacct -P -n --units=K` rows. The allocation row carries
// what was asked for; usage lives on the .batch step where the workload actually
// runs, since .extern and any poll step would mask it with near-zero values.
func parseSacctUtil(output string) RunStats {
	var rows [][]string
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			rows = append(rows, strings.Split(trimmed, "|"))
		}
	}
	if len(rows) == 0 {
		return RunStats{}
	}
	alloc, usage := rows[0], rows[0]
	for _, row := range rows {
		if !strings.Contains(row[0], ".") {
			alloc = row
			break
		}
	}
	for _, row := range rows {
		if strings.HasSuffix(row[0], ".batch") {
			usage = row
			break
		}
	}

	stats := RunStats{}
	if cores, err := strconv.Atoi(strings.TrimSpace(field(alloc, 1))); err == nil && cores > 0 {
		stats.Cores = cores
	}
	if elapsed, err := strconv.ParseInt(strings.TrimSpace(field(alloc, 3)), 10, 64); err == nil {
		stats.ElapsedSeconds = elapsed
	}
	requestedKiB, hasRequested := parseKiB(field(alloc, 2))
	allocCPUSeconds, _ := strconv.ParseFloat(strings.TrimSpace(field(alloc, 4)), 64)
	maxRSSKiB, hasMaxRSS := parseKiB(field(usage, 5))
	usedCPUSeconds := hmsSeconds(field(usage, 6))

	if hasRequested {
		stats.RequestedMemory = humanKiB(requestedKiB)
	}
	if hasMaxRSS {
		stats.MaxRSS = humanKiB(maxRSSKiB)
	}
	// TotalCPU reads 00:00:00 until the step ends, so a zero means the flush has
	// not landed rather than that the job sat idle.
	if usedCPUSeconds > 0 && allocCPUSeconds > 0 {
		stats.CPUEfficiencyPct = usedCPUSeconds / allocCPUSeconds * 100
	}
	if hasMaxRSS && hasRequested && requestedKiB > 0 {
		stats.MemoryEfficiencyPct = maxRSSKiB / requestedKiB * 100
	}
	return stats
}

func field(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return row[index]
}

// With --units=K every memory field is KiB, so the value is its leading number:
// this drops the trailing K and any legacy per-CPU or per-node suffix.
func parseKiB(value string) (float64, bool) {
	text := strings.TrimSpace(value)
	end := 0
	for end < len(text) && (text[end] >= '0' && text[end] <= '9' || text[end] == '.' || end == 0 && (text[end] == '-' || text[end] == '+')) {
		end++
	}
	number, err := strconv.ParseFloat(text[:end], 64)
	return number, err == nil
}

func humanKiB(kib float64) string {
	switch {
	case kib >= 1024*1024:
		return fmt.Sprintf("%.1f GB", kib/(1024*1024))
	case kib >= 1024:
		return fmt.Sprintf("%.1f MB", kib/1024)
	default:
		return fmt.Sprintf("%.0f KB", kib)
	}
}

// Slurm writes a consumed-CPU duration as [DD-]HH:MM:SS or MM:SS; TotalCPU is
// the one field with no raw-seconds twin, so it has to be read this way.
func hmsSeconds(value string) float64 {
	text := strings.TrimSpace(value)
	if text == "" {
		return 0
	}
	days, rest := "0", text
	if before, after, found := strings.Cut(text, "-"); found {
		days, rest = before, after
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return 0
	}
	seconds := 0.0
	for _, part := range parts {
		value, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			return 0
		}
		seconds = seconds*60 + value
	}
	dayCount, err := strconv.ParseFloat(strings.TrimSpace(days), 64)
	if err != nil {
		return 0
	}
	return dayCount*86400 + seconds
}
