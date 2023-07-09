package router

import (
	"github.com/Zubayear/fujibayashi/handler"
	"github.com/Zubayear/fujibayashi/middleware"
	"github.com/Zubayear/fujibayashi/repo"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"io"
)

// SetupRouter provide api endpoints
func SetupRouter(userRepo repo.UserRepositoryImpl, roleRepo repo.RoleRepositoryImpl, logger *zap.Logger) *gin.Engine {
	// Disable Gin's default console logging
	gin.DefaultWriter = io.Discard

	router := gin.New()

	router.Use(gin.Recovery(), middleware.LoggingMiddleware(logger))

	// Apply CORS middleware
	config := cors.DefaultConfig()
	config.AllowCredentials = true
	config.AllowOrigins = []string{"http://localhost:3000"} // Replace with your allowed origins
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}

	router.POST("/api/v1/register", handler.RegisterHandler(userRepo, logger))
	router.POST("/api/v1/login", handler.LoginHandler(userRepo, logger))

	//router.Use(middleware.IsAuthenticated(logger))
	router.POST("/api/v1/logout", middleware.IsAuthenticated(logger), handler.LogoutHandler(userRepo, logger))
	router.POST("/api/v1/user", middleware.IsAuthenticated(logger), handler.UserHandler(userRepo, logger))
	router.GET("/api/v1/users/:id", middleware.IsAuthenticated(logger), handler.UserByIdHandler(userRepo, logger))
	router.PUT("/api/v1/users/:id", middleware.IsAuthenticated(logger), handler.UpdateUserHandler(userRepo, logger))
	router.DELETE("/api/v1/users/:id", middleware.IsAuthenticated(logger), handler.DeleteUserHandler(userRepo, logger))

	// roles routes
	router.POST("/api/v1/roles", middleware.IsAuthenticated(logger), handler.RoleCreateHandler(roleRepo, logger))
	router.GET("/api/v1/roles/:id", middleware.IsAuthenticated(logger), handler.RolesHandler(roleRepo, logger))
	router.PUT("/api/v1/roles/:id", middleware.IsAuthenticated(logger), handler.UpdateRoleHandler(roleRepo, logger))
	router.DELETE("/api/v1/roles/:id", middleware.IsAuthenticated(logger), handler.DeleteRoleHandler(roleRepo, logger))
	router.Use(cors.New(config))

	return router
}
