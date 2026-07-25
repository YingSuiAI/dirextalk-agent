package coreruntime

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type CronCalculator struct{}

func NewCronCalculator() CronCalculator { return CronCalculator{} }

func (CronCalculator) Next(after time.Time, expression, timezone string) (time.Time, error) {
	parsed, err := coretask.ParseCron(expression)
	if err != nil {
		return time.Time{}, err
	}
	loc, err := time.LoadLocation(strings.TrimSpace(timezone))
	if err != nil {
		return time.Time{}, err
	}
	start := after.UTC().Truncate(time.Minute).Add(time.Minute)
	sets := [5]map[int]bool{}
	for i, f := range parsed.Fields {
		sets[i], err = parseField(f, i)
		if err != nil {
			return time.Time{}, err
		}
	}
	for n := 0; n < 60*24*366*10; n++ {
		u := start.Add(time.Duration(n) * time.Minute)
		l := u.In(loc)
		if !sets[0][l.Minute()] || !sets[1][l.Hour()] || !sets[3][int(l.Month())] {
			continue
		}
		dom, dow := sets[2][l.Day()], sets[4][int(l.Weekday())]
		domWildcard, dowWildcard := parsed.Fields[2] == "*", parsed.Fields[4] == "*"
		if domWildcard && dowWildcard {
			// unrestricted day fields match every day
		} else if domWildcard && !dow || dowWildcard && !dom || !domWildcard && !dowWildcard && !(dom || dow) {
			continue
		}
		return u, nil
	}
	return time.Time{}, fmt.Errorf("no cron occurrence within search horizon")
}

func parseField(field string, pos int) (map[int]bool, error) {
	min, max := [...]int{0, 0, 1, 1, 0}[pos], [...]int{59, 23, 31, 12, 7}[pos]
	out := map[int]bool{}
	for _, item := range strings.Split(field, ",") {
		step := 1
		if strings.Contains(item, "/") {
			p := strings.SplitN(item, "/", 2)
			item = p[0]
			var err error
			step, err = strconv.Atoi(p[1])
			if err != nil || step <= 0 {
				return nil, coretask.ErrInvalid
			}
		}
		lo, hi := min, max
		if item != "*" {
			if strings.Contains(item, "-") {
				p := strings.SplitN(item, "-", 2)
				var e error
				lo, e = strconv.Atoi(p[0])
				if e != nil {
					return nil, coretask.ErrInvalid
				}
				hi, e = strconv.Atoi(p[1])
				if e != nil {
					return nil, coretask.ErrInvalid
				}
			} else {
				var e error
				lo, e = strconv.Atoi(item)
				if e != nil {
					return nil, coretask.ErrInvalid
				}
				hi = lo
			}
		}
		if lo < min || hi > max || lo > hi {
			return nil, coretask.ErrInvalid
		}
		for v := lo; v <= hi; v += step {
			out[v] = true
			if pos == 4 && v == 7 {
				out[0] = true // cron's 7 is Sunday; time.Weekday uses 0.
			}
		}
	}
	return out, nil
}
