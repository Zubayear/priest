package middleware

import (
	"bytes"
	"github.com/Zubayear/fujibayashi/auth"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"time"
)

func LoggingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// CreateUser a new buffer to capture the response body
		buffer := bytes.NewBuffer(nil)

		// CreateUser a new response writer that writes to our buffer
		captureWriter := NewCaptureResponseWriter(c.Writer, buffer)

		// Replace the original writer with our capture writer
		c.Writer = captureWriter

		logger.Info("Request received",
			zap.String("path", c.Request.URL.Path),
			zap.String("ip", c.ClientIP()),
			zap.String("method", c.Request.Method),
			zap.Any("headers", c.Request.Header),
			zap.Any("query", c.Request.URL.Query()),
		)

		c.Next()

		latency := time.Since(start)

		// Log the response body
		responseBody := buffer.String()

		logger.Info("Response sent",
			zap.Int("status", c.Writer.Status()),
			zap.Float64("latency", latency.Seconds()),
			zap.Any("headers", c.Writer.Header()),
			zap.Any("response_body", responseBody),
		)
	}
}

func IsAuthenticated(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		jwt, err := c.Cookie("refreshToken")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
			return
		}
		_, err = auth.ValidateRefreshToken(jwt)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
			return
		}
		c.Next()
	}
}

// CaptureResponseWriter is a custom response writer that captures the response data
type CaptureResponseWriter struct {
	gin.ResponseWriter
	buffer *bytes.Buffer
}

func NewCaptureResponseWriter(w gin.ResponseWriter, buffer *bytes.Buffer) *CaptureResponseWriter {
	return &CaptureResponseWriter{
		ResponseWriter: w,
		buffer:         buffer,
	}
}

func (c *CaptureResponseWriter) Write(b []byte) (int, error) {
	c.buffer.Write(b)
	return c.ResponseWriter.Write(b)
}
