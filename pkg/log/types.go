package log

import (
	"log"
)

var cli *Logger

type logLevel int
// LogLevel map
const (
	DebugLevel logLevel = iota + 1
	InfoLevel
	ErrorLevel
)

var levels = map[string]logLevel{
	"debug": DebugLevel,
	"info":  InfoLevel,
	"error": ErrorLevel,
}

// Logger is log client
type Logger struct {
	level  logLevel
	caller bool
}

// New returns new Logger pointer
func New(levelStr string) error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	level, ok := levels[levelStr]
	if !ok {
		log.Printf("log level must debug/info/error, you given %q\n", levelStr)
		level = InfoLevel
	}
	cli = &Logger{
		level:  level,
		caller: true,
	}
	return nil
}
