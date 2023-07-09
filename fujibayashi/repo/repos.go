package repo

import (
	"github.com/Zubayear/fujibayashi/model"
	"gorm.io/gorm"
)

type UserRepository interface {
	CreateUser(user *model.User) (error, int64)
	QueryUser(email string) (error, *model.User)
	QueryById(id uint64) (error, *model.User)
	UpdateUser(user *model.User) (error, int64)
	DeleteUser(user *model.User) (error, int64)
}

type RoleRepository interface {
	CreateRole(role *model.Role) (error, int64)
	QueryRoles() (error, []*model.Role)
	UpdateRole(role *model.Role) (error, int64)
	DeleteRole(role *model.Role) (error, int64)
}

type RoleRepositoryImpl struct {
	db *gorm.DB
}

func (r *RoleRepositoryImpl) CreateRole(role *model.Role) (error, int64) {
	result := r.db.Create(role)
	return result.Error, result.RowsAffected
}

func (r *RoleRepositoryImpl) QueryRoles() (error, []*model.Role) {
	var roles []*model.Role
	result := r.db.Find(&roles)
	return result.Error, roles
}

func (r *RoleRepositoryImpl) UpdateRole(role *model.Role) (error, int64) {
	result := r.db.Model(role).Updates(role)
	return result.Error, result.RowsAffected

}

func (r *RoleRepositoryImpl) DeleteRole(role *model.Role) (error, int64) {
	result := r.db.Delete(role)
	return result.Error, result.RowsAffected
}

func NewRoleRepositoryImpl(db *gorm.DB) *RoleRepositoryImpl {
	return &RoleRepositoryImpl{db: db}
}

type UserRepositoryImpl struct {
	db *gorm.DB
}

func NewUserRepositoryImpl(db *gorm.DB) *UserRepositoryImpl {
	return &UserRepositoryImpl{db: db}
}

func (u *UserRepositoryImpl) CreateUser(user *model.User) (error, int64) {
	result := u.db.Create(user)
	return result.Error, result.RowsAffected
}

func (u *UserRepositoryImpl) QueryUser(email string) (error, *model.User) {
	var user model.User
	u.db.Where("email = ?", email).First(&user)
	return nil, &user
}

func (u *UserRepositoryImpl) QueryById(id uint64) (error, *model.User) {
	var user model.User
	u.db.Where("id = ?", id).First(&user)
	return nil, &user
}

func (u *UserRepositoryImpl) UpdateUser(user *model.User) (error, int64) {
	result := u.db.Model(&user).Updates(user)
	return result.Error, result.RowsAffected
}

func (u *UserRepositoryImpl) DeleteUser(user *model.User) (error, int64) {
	result := u.db.Delete(&user)
	return result.Error, result.RowsAffected
}
