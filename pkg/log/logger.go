package log

import (
	"fmt"
	"log"
	"os"
)

func (l *Logger) enablePut(level logLevel) bool {
	return l.level <= level
}

// Debug is
func Debug(msg ...interface{}) {
	if cli.enablePut(DebugLevel) {
		log.Output(2, fmt.Sprint(msg...))
	}
}

// Debugf is
func Debugf(format string, msg ...interface{}) {
	if cli.enablePut(DebugLevel) {
		log.Output(2, fmt.Sprintf(format, msg...))
	}
}

// Info is
func Info(msg ...interface{}) {
	if cli.enablePut(InfoLevel) {
		log.Output(2, fmt.Sprint(msg...))
	}
}

// Infof is
func Infof(format string, msg ...interface{}) {
	if cli.enablePut(InfoLevel) {
		log.Output(2, fmt.Sprintf(format, msg...))
	}
}

// Error is
func Error(msg ...interface{}) {
	if cli.enablePut(ErrorLevel) {
		log.Output(2, fmt.Sprint(msg...))
		if cli.caller {
			st := fetchStackTraceFrame(defaultSkipCaller)
			for _, trace := range st {
				log.Println(trace)
			}
		}
	}
}

// Errorf is
func Errorf(format string, msg ...interface{}) {
	if cli.enablePut(ErrorLevel) {
		log.Output(2, fmt.Sprintf(format, msg...))
		if cli.caller {
			st := fetchStackTraceFrame(defaultSkipCaller)
			for _, trace := range st {
				log.Println(trace)
			}
		}
	}
}

// Fatal is
func Fatal(msg ...interface{}) {
	log.Output(2, fmt.Sprint(msg...))
	if cli.caller {
		st := fetchStackTraceFrame(defaultSkipCaller)
		for _, trace := range st {
			log.Println(trace)
		}
	}
	os.Exit(1)
}

// Fatalf is
func Fatalf(format string, msg ...interface{}) {
	log.Output(2, fmt.Sprintf(format, msg...))
	if cli.caller {
		st := fetchStackTraceFrame(defaultSkipCaller)
		for _, trace := range st {
			log.Println(trace)
		}
	}
	os.Exit(1)
}
