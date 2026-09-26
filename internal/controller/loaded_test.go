package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoadingStateBacksOffThenTimesOut(t *testing.T) {
	cases := []struct {
		elapsed time.Duration
		reason  string
		after   time.Duration
	}{
		{0, "Loading", 20 * time.Millisecond},
		{900 * time.Millisecond, "Loading", 20 * time.Millisecond},
		{3 * time.Second, "Loading", 500 * time.Millisecond},
		{20 * time.Second, "Loading", 2 * time.Second},
		{time.Minute, "Timeout", timedOutRecheck},
		{time.Hour, "Timeout", timedOutRecheck},
	}
	for _, c := range cases {
		st, reason, after := loadingState(c.elapsed, time.Minute)
		if st != metav1.ConditionFalse || reason != c.reason || after != c.after {
			t.Errorf("%s: got %s/%s/%s", c.elapsed, st, reason, after)
		}
	}
}
