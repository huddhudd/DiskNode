package usersave

import "time"

const (
	ticksPerSecond            = int64(10_000_000)
	unixToWindowsEpochSeconds = int64(11644473600)
)

func timeToFiletime(t time.Time) int64 {
	utc := t.UTC()
	secs := utc.Unix() + unixToWindowsEpochSeconds
	return secs*ticksPerSecond + int64(utc.Nanosecond()/100)
}

func filetimeToUnixSeconds(ft int64) int64 {
	if ft <= 0 {
		return 0
	}
	secs := ft / ticksPerSecond
	return secs - unixToWindowsEpochSeconds
}

func nowFiletime() int64 {
	return timeToFiletime(time.Now())
}
