// Package flow provides online statistical computations using Welford's algorithm.
// This enables O(1) memory and O(1) per-update complexity for computing mean,
// variance, and standard deviation incrementally.
package flow

import (
	"math"
)

// RunningStats tracks running statistics (mean, variance, min, max) for a stream
// of values using Welford's online algorithm.
//
// Welford's Algorithm:
//   - Numerically stable (avoids catastrophic cancellation)
//   - O(1) memory (no array storage)
//   - O(1) per update
//
// Reference: Welford, B. P. (1962). "Note on a method for calculating
// corrected sums of squares and products"
type RunningStats struct {
	n    int64   // Count of values
	mean float64 // Running mean
	m2   float64 // Sum of squared differences from mean (for variance)
	min  float64 // Minimum value seen
	max  float64 // Maximum value seen
	sum  float64 // Running sum (for total calculations)
}

// NewStats creates a new RunningStats instance.
func NewStats() *RunningStats {
	return &RunningStats{
		min: math.MaxFloat64,
		max: -math.MaxFloat64,
	}
}

// Update adds a new value to the running statistics.
// This implements Welford's online algorithm for numerically stable
// variance computation.
func (s *RunningStats) Update(x float64) {
	s.n++
	s.sum += x

	// Welford's algorithm for online mean and variance
	delta := x - s.mean
	s.mean += delta / float64(s.n)
	delta2 := x - s.mean
	s.m2 += delta * delta2

	// Update min/max
	if x < s.min {
		s.min = x
	}
	if x > s.max {
		s.max = x
	}
}

// Count returns the number of values seen.
func (s *RunningStats) Count() int64 {
	return s.n
}

// Sum returns the total sum of all values.
func (s *RunningStats) Sum() float64 {
	return s.sum
}

// Mean returns the arithmetic mean of all values.
// Returns 0 if no values have been added.
func (s *RunningStats) Mean() float64 {
	if s.n == 0 {
		return 0
	}
	return s.mean
}

// Variance returns the sample variance (using n-1 denominator).
// Returns 0 if fewer than 2 values have been added.
func (s *RunningStats) Variance() float64 {
	if s.n < 2 {
		return 0
	}
	return s.m2 / float64(s.n-1)
}

// StdDev returns the sample standard deviation.
// Returns 0 if fewer than 2 values have been added.
func (s *RunningStats) StdDev() float64 {
	return math.Sqrt(s.Variance())
}

// Min returns the minimum value seen.
// Returns 0 if no values have been added.
func (s *RunningStats) Min() float64 {
	if s.n == 0 {
		return 0
	}
	return s.min
}

// Max returns the maximum value seen.
// Returns 0 if no values have been added.
func (s *RunningStats) Max() float64 {
	if s.n == 0 {
		return 0
	}
	return s.max
}

// Reset clears all statistics.
func (s *RunningStats) Reset() {
	s.n = 0
	s.mean = 0
	s.m2 = 0
	s.min = math.MaxFloat64
	s.max = -math.MaxFloat64
	s.sum = 0
}

// Clone creates a copy of the current stats.
func (s *RunningStats) Clone() *RunningStats {
	return &RunningStats{
		n:    s.n,
		mean: s.mean,
		m2:   s.m2,
		min:  s.min,
		max:  s.max,
		sum:  s.sum,
	}
}
