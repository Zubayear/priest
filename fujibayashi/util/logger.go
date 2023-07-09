package util

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var loggerInstance *zap.Logger

func init() {
	if loggerInstance == nil {
		prodEncoderConfig := zap.NewProductionEncoderConfig()
		prodEncoderConfig.EncodeTime = CustomTimeEncoder
		// CreateUser a console encoder
		consoleEncoder := zapcore.NewConsoleEncoder(prodEncoderConfig)

		// CreateUser a file encoder
		_ = zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())

		// CreateUser a console write syncer
		consoleWriteSyncer := zapcore.AddSync(os.Stdout)

		// CreateUser a file write syncer
		file, err := os.OpenFile(fmt.Sprintf("log-%s.log", time.Now().Format("2006-01-02")), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		fileWriteSyncer := zapcore.AddSync(file)

		// Combine the console and file write syncers
		combinedWriteSyncer := zapcore.NewMultiWriteSyncer(consoleWriteSyncer, fileWriteSyncer)

		// CreateUser a core with the combined write syncer
		core := zapcore.NewCore(
			// Use the console encoder and console write syncer for debug and info levels
			consoleEncoder,
			combinedWriteSyncer,
			zap.NewAtomicLevelAt(zap.DebugLevel),
		)

		// CreateUser a logger with the core
		loggerInstance = zap.New(core)
	}

	// Defer a call to logger.Sync() to flush any buffered log messages
	defer func(loggerInstance *zap.Logger) {
		err := loggerInstance.Sync()
		if err != nil {
			fmt.Println("error occurred closing logger", err.Error())
		}
	}(loggerInstance)
}

func GetLogger() *zap.Logger {
	return loggerInstance
}

func CustomTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02T15:04:05.999Z07:00")) // Replace this format with your desired format
}
