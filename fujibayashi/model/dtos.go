package model

type RegisterDto struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleId   uint   `json:"roleId"`
}

type LoginDto struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RoleDto struct {
	Name        string `json:"name"`
	Permissions []int  `json:"permissions"`
}
