package model

type User struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
}

func (u *User) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"id":       u.Id,
		"username": u.Username,
	}
}
