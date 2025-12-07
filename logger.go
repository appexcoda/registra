package main

import (
	"log"
	"os"
	"strings"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

type Logger struct {
	level  LogLevel
	logger *log.Logger
}

func NewLogger(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		l.logger.Printf("[DEBUG] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		l.logger.Printf("[INFO] "+format, v...)
	}
}

func (l *Logger) Warn(format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		l.logger.Printf("[WARN] "+format, v...)
	}
}

func (l *Logger) Error(format string, v ...interface{}) {
	if l.level <= LogLevelError {
		l.logger.Printf("[ERROR] "+format, v...)
	}
}

func (l *Logger) DebugWithID(requestID, format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		l.logger.Printf("[DEBUG] [%s] "+format, append([]interface{}{requestID}, v...)...)
	}
}

func (l *Logger) InfoWithID(requestID, format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		l.logger.Printf("[INFO] [%s] "+format, append([]interface{}{requestID}, v...)...)
	}
}

func (l *Logger) WarnWithID(requestID, format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		l.logger.Printf("[WARN] [%s] "+format, append([]interface{}{requestID}, v...)...)
	}
}

func (l *Logger) ErrorWithID(requestID, format string, v ...interface{}) {
	if l.level <= LogLevelError {
		l.logger.Printf("[ERROR] [%s] "+format, append([]interface{}{requestID}, v...)...)
	}
}

var AppLogger *Logger

func InitLogger(levelStr string) {
	var level LogLevel
	levelName := strings.ToLower(levelStr)

	switch levelName {
	case "debug":
		level = LogLevelDebug
	case "info":
		level = LogLevelInfo
	case "warn":
		level = LogLevelWarn
	case "error":
		level = LogLevelError
	default:
		level = LogLevelInfo
	}

	AppLogger = NewLogger(level)
}

func init() {
	AppLogger = NewLogger(LogLevelInfo)
}
