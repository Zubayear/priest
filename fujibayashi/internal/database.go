package internal

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func ConnectDb() *gorm.DB {
	dsn := "root:root@tcp(127.0.0.1:3306)/kaisen?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn))
	if err != nil {
		return nil
	}
	return db
}
