package log

import (
	"fmt"
	"runtime"
)

type stackTrace []string

// skip wrap func steps
// runtime.Callers => fetchStacktrace => logger.Errorf
const defaultSkipCaller = 3

// stacktrace時に、10ステップ前まで遡る
const traceCaller = 10

func fetchStackTraceFrame(skipCaller int) []string {
	pc := make([]uintptr, traceCaller)
	n := runtime.Callers(skipCaller, pc)
	if n == 0 {
		return stackTrace{}
	}
	// ready for skip last call function
	lastCaller := 0
	for _, p := range pc {
		if p == 0x0 {
			continue
		}
		lastCaller++
	}
	// delete last call function : runtime.exit
	if lastCaller <= traceCaller {
		pc = pc[:(lastCaller - 1)]
	}
	st := make([]string, 0, lastCaller)
	// frame単位で保存する
	frames := runtime.CallersFrames(pc)
	for {
		frame, more := frames.Next()
		st = append(st, fmt.Sprintf("%s=>%s:%d", frame.Function, frame.File, frame.Line))
		if !more {
			break
		}
	}
	return st
}
