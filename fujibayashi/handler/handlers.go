package handler

import (
	"github.com/Zubayear/fujibayashi/auth"
	"github.com/Zubayear/fujibayashi/model"
	"github.com/Zubayear/fujibayashi/repo"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"net/http"
	"strconv"
	"time"
)

func RegisterHandler(repo repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user model.RegisterDto
		err := c.ShouldBindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid parameter"})
			return
		}
		hashedPass, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "password hashing failed"})
			return
		}
		entity := &model.User{
			Email:    user.Email,
			Password: string(hashedPass),
			RoleId:   user.RoleId,
		}
		err, r := repo.CreateUser(entity)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if r >= 1 {
			c.JSON(http.StatusCreated, gin.H{"message": "user created"})
		}
	}
}

func LoginHandler(repo repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginDto model.LoginDto
		err := c.ShouldBindJSON(&loginDto)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid parameter"})
			return
		}
		err, u := repo.QueryUser(loginDto.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if u.ID == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "user not registered"})
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(loginDto.Password))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "password doesn't match"})
			return
		}
		token, err := auth.GenerateJWT(u.Email, []string{"user", "admin"})
		refreshToken, err := auth.GenerateRefreshToken(u.Email)
		cookie := http.Cookie{
			Name:     "refreshToken",
			Value:    refreshToken,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour), // Set an expiration time for the cookie
			HttpOnly: true,
		}

		// Set the cookie in the response
		http.SetCookie(c.Writer, &cookie)
		c.JSON(http.StatusOK, gin.H{"token": token})
	}
}

func UserHandler(repo repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken, err := c.Cookie("refreshToken")
		jwt, err := auth.ValidateRefreshToken(refreshToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "refresh token not valid"})
			return
		}
		email, _ := jwt["username"].(string)
		err, user := repo.QueryUser(email)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
			return
		}

		rsp := model.LoginDto{
			Email:    user.Email,
			Password: user.Password,
		}

		cookie := http.Cookie{
			Name:     "refreshToken",
			Value:    refreshToken,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour), // Set an expiration time for the cookie
			HttpOnly: true,
		}

		// Set the cookie in the response
		http.SetCookie(c.Writer, &cookie)
		c.JSON(http.StatusOK, gin.H{"data": rsp})
	}
}

func UserByIdHandler(repo repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		parsedId, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		err, user := repo.QueryById(parsedId)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
			return
		}
		if user.ID == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": user})
	}
}

func LogoutHandler(_ repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		cookie := http.Cookie{
			Name:     "refreshToken",
			Value:    "",
			Path:     "/",
			Expires:  time.Now().Add(-time.Hour), // Set an expiration time for the cookie
			HttpOnly: true,
		}

		// Set the cookie in the response
		http.SetCookie(c.Writer, &cookie)
		c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
	}
}

func UpdateUserHandler(repo repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		parsedId, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		var loginDto model.LoginDto
		err = c.ShouldBindJSON(&loginDto)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		var user model.User
		if loginDto.Password != "" {
			hashedPass, err := bcrypt.GenerateFromPassword([]byte(loginDto.Password), 10)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			user.Password = string(hashedPass)
		}
		user.ID = uint(parsedId)
		user.Email = loginDto.Email
		err, row := repo.UpdateUser(&user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
			return
		}
		if row >= 1 {
			c.JSON(http.StatusNoContent, gin.H{"message": "success"})
			return
		}
	}
}

func DeleteUserHandler(repo repo.UserRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		parsedId, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		var user model.User

		user.ID = uint(parsedId)
		err, row := repo.DeleteUser(&user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
			return
		}
		if row >= 1 {
			c.JSON(http.StatusNoContent, gin.H{"message": "success"})
			return
		}
	}
}

func RoleCreateHandler(repo repo.RoleRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var role model.RoleDto
		err := c.ShouldBindJSON(&role)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid parameter"})
			return
		}

		permissions := make([]model.Permission, len(role.Permissions))

		for i, permission := range role.Permissions {
			permissions[i] = model.Permission{Model: gorm.Model{ID: uint(permission)}}
		}

		entity := &model.Role{
			Name:        role.Name,
			Permissions: permissions,
		}
		logger.Info("role", zap.Any("entity", entity))

		err, r := repo.CreateRole(entity)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if r >= 1 {
			c.JSON(http.StatusCreated, gin.H{"message": "role created"})
			return
		}
	}
}

func RolesHandler(repo repo.RoleRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		err, r := repo.QueryRoles()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": r})
	}
}

func UpdateRoleHandler(repo repo.RoleRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		parsedId, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		var roleDto model.RoleDto
		err = c.ShouldBindJSON(&roleDto)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		var role model.Role
		role.ID = uint(parsedId)
		err, r := repo.UpdateRole(&role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if r >= 1 {
			c.JSON(http.StatusNoContent, gin.H{"message": "role updated"})
		}
	}
}

func DeleteRoleHandler(repo repo.RoleRepositoryImpl, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		parsedId, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		var role model.Role

		role.ID = uint(parsedId)
		err, row := repo.DeleteRole(&role)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
			return
		}
		if row >= 1 {
			c.JSON(http.StatusNoContent, gin.H{"message": "success"})
			return
		}
	}
}
