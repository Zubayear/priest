package main

import (
	"github.com/Zubayear/fujibayashi/internal"
	"github.com/Zubayear/fujibayashi/model"
	"github.com/Zubayear/fujibayashi/repo"
	"github.com/Zubayear/fujibayashi/router"
	"github.com/Zubayear/fujibayashi/util"
)

var (
	// logger
	logger = util.GetLogger()
)

func main() {
	db := internal.ConnectDb()
	db.AutoMigrate(&model.User{}, &model.Role{}, &model.Permission{})
	userRepo := repo.NewUserRepositoryImpl(db)
	roleRepo := repo.NewRoleRepositoryImpl(db)
	engine := router.SetupRouter(*userRepo, *roleRepo, logger)
	engine.Run(":8080")
}
