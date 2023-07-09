package model

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
	RoleId   uint
	Role     Role `gorm:"foreignKey:RoleId"`
}

type Role struct {
	gorm.Model
	Name        string
	Permissions []Permission `gorm:"many2many:roles_permission"`
}

type Permission struct {
	gorm.Model
	Name string
}
