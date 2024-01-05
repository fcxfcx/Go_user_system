package service

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"user_system/internal/cache"
	"user_system/internal/dao"
	"user_system/internal/model"
	"user_system/pkg/constant"
	"user_system/utils"
)

// Register 用户注册
func Register(req *RegisterRequest) error {
	// 判断注册提交的参数是否符合要求
	if req.UserName == "" || req.Password == "" || req.Age <= 0 || !utils.Contains([]string{constant.GenderMale, constant.GenderFeMale}, req.Gender) {
		log.Errorf("register param invalid")
		return fmt.Errorf("register param invalid")
	}
	// DAO层验证用户名是否已注册
	existedUser, err := dao.GetUserByName(req.UserName)
	if err != nil {
		log.Errorf("Register|%v", err)
		return fmt.Errorf("register|%v", err)
	}
	if existedUser != nil {
		log.Errorf("用户已经注册,user_name==%s", req.UserName)
		return fmt.Errorf("用户已经注册，不能重复注册")
	}
	// 验证通过，开始准备注册流程
	user := &model.User{
		Name:     req.UserName,
		Age:      req.Age,
		Gender:   req.Gender,
		PassWord: req.Password,
		NickName: req.NickName,
		CreateModel: model.CreateModel{
			Creator: req.UserName,
		},
		ModifyModel: model.ModifyModel{
			Modifier: req.UserName,
		},
	}
	log.Infof("user ====== %+v", user)
	// DAO层向数据库中添加用户数据
	if err := dao.CreateUser(user); err != nil {
		log.Errorf("Register|%v", err)
		return fmt.Errorf("register|%v", err)
	}
	return nil
}

// Login 用户登陆
func Login(ctx context.Context, req *LoginRequest) (string, error) {
	uuid := ctx.Value(constant.ReqUuid)
	log.Debugf(" %s| Login access from:%s,@,%s", uuid, req.UserName, req.PassWord)

	user, err := getUserInfo(req.UserName)
	if err != nil {
		log.Errorf("Login|%v", err)
		return "", fmt.Errorf("login|%v", err)
	}

	// 用户存在
	if req.PassWord != user.PassWord {
		log.Errorf("Login|password err: req.password=%s|user.password=%s", req.PassWord, user.PassWord)
		return "", fmt.Errorf("password is not correct")
	}

	session := utils.GenerateSession(user.Name)
	err = cache.SetSessionInfo(user, session)

	if err != nil {
		log.Errorf(" Login|Failed to SetSessionInfo, uuid=%s|user_name=%s|session=%s|err=%v", uuid, user.Name, session, err)
		return "", fmt.Errorf("login|SetSessionInfo fail:%v", err)
	}

	log.Infof("Login successfully, %s@%s with redis_session session_%s", req.UserName, req.PassWord, session)
	return session, nil
}

// Logout 退出登陆
func Logout(ctx context.Context, req *LogoutRequest) error {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|Logout access from,user_name=%s|session=%s", uuid, req.UserName, session)
	// 要退出登录，必须要是在登录态
	_, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("Logout|GetSessionInfo err:%v", err)
	}

	err = cache.DelSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to delSessionInfo :%s", uuid, session)
		return fmt.Errorf("del session err:%v", err)
	}
	log.Infof("%s|Success to delSessionInfo :%s", uuid, session)
	return nil
}

// Logoff 用户注销
func Logoff(ctx context.Context, req *LogoffRequest) error {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|Logoff access from,user_name=%s|session=%s", uuid, req.UserName, session)
	// 要注销用户，必须要是在登录态
	_, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("Logoff|GetSessionInfo err:%v", err)
	}

	err = cache.DelSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to delSessionInfo :%s", uuid, session)
		return fmt.Errorf("del session err:%v", err)
	}
	log.Infof("%s|Success to delSessionInfo :%s", uuid, session)
	return deleteUser(req.UserName, session)
}

// GetUserInfo 获取用户信息请求，只能在用户登陆的情况下使用
func GetUserInfo(ctx context.Context, req *GetUserInfoRequest) (*GetUserInfoResponse, error) {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|GetUserInfo access from,user_name=%s|session=%s", uuid, req.UserName, session)

	if session == "" || req.UserName == "" {
		return nil, fmt.Errorf("GetUserInfo|request params invalid")
	}

	user, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return nil, fmt.Errorf("getUserInfo|GetSessionInfo err:%v", err)
	}

	if user.Name != req.UserName {
		log.Errorf("%s|session info not match with username=%s", uuid, req.UserName)
	}
	log.Infof("%s|Succ to GetUserInfo|user_name=%s|session=%s", uuid, req.UserName, session)
	return &GetUserInfoResponse{
		UserName: user.Name,
		Age:      user.Age,
		Gender:   user.Gender,
		PassWord: user.PassWord,
		NickName: user.NickName,
		HeadUrl:  user.HeadUrl,
	}, nil
}

func UpdateUserNickName(ctx context.Context, req *UpdateNickNameRequest) error {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|UpdateUserNickName access from,user_name=%s|session=%s", uuid, req.UserName, session)
	log.Infof("UpdateUserNickName|req==%v", req)

	if session == "" || req.UserName == "" {
		return fmt.Errorf("UpdateUserNickName|request params invalid")
	}

	user, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("UpdateUserNickName|GetSessionInfo err:%v", err)
	}

	if user.Name != req.UserName {
		log.Errorf("UpdateUserNickName|%s|session info not match with username=%s", uuid, req.UserName)
	}

	updateUser := &model.User{
		NickName: req.NewNickName,
	}

	return updateUserInfo(updateUser, req.UserName, session)
}

func UploadPic(ctx context.Context, username string, path string) error {
	uuid := ctx.Value(constant.ReqUuid)
	session := ctx.Value(constant.SessionKey).(string)
	log.Infof("%s|UploadPic access from,user_name=%s|session=%s", uuid, username, session)
	if session == "" || username == "" {
		return fmt.Errorf("UploadPic|request params invalid")
	}

	user, err := cache.GetSessionInfo(session)
	if err != nil {
		log.Errorf("%s|Failed to get with session=%s|err =%v", uuid, session, err)
		return fmt.Errorf("UploadPic|GetSessionInfo err:%v", err)
	}

	if user.Name != username {
		log.Errorf("UploadPic|%s|session info not match with username=%s", uuid, username)
	}

	updateUser := &model.User{
		HeadUrl: path,
	}
	return updateUserInfo(updateUser, username, session)
}

func getUserInfo(userName string) (*model.User, error) {
	// 优先从redis缓存中提取
	user, err := cache.GetUserInfoFromCache(userName)
	// 缓存中读取成功直接返回
	if err == nil && user.Name == userName {
		log.Infof("cache_user ======= %v", user)
		return user, nil
	}

	// 缓存未读取成功，进入DAO层去数据库中读取
	user, err = dao.GetUserByName(userName)
	// 如果查询过程出错了就返回错误
	if err != nil {
		return user, err
	}
	// 根据用户名未查询到数据，则返回错误
	if user == nil {
		return nil, fmt.Errorf("用户尚未注册")
	}

	log.Infof("user === %+v", user)
	// 如果查询到了用户则向redis缓存中加入它
	err = cache.SetUserCacheInfo(user)
	if err != nil {
		log.Error("cache userinfo failed for user:", user.Name, " with err:", err.Error())
	}
	log.Infof("getUserInfo successfully, with key userinfo_%s", user.Name)
	return user, nil
}

func updateUserInfo(user *model.User, userName, session string) error {
	affectedRows := dao.UpdateUserInfo(userName, user)

	// db更新成功
	if affectedRows == 1 {
		user, err := dao.GetUserByName(userName)
		if err == nil {
			cache.UpdateCachedUserInfo(user)
			if session != "" {
				err = cache.SetSessionInfo(user, session)
				if err != nil {
					log.Error("update session failed:", err.Error())
					cache.DelSessionInfo(session)
				}
			}
		} else {
			log.Error("Failed to get dbUserInfo for cache, username=%s with err:", userName, err.Error())
		}
	}
	return nil
}

func deleteUser(userName, session string) error {
	affectedRows := dao.DeleteUser(userName)

	// db更新成功
	if affectedRows == 1 {
		// 再次判断
		user, err := dao.GetUserByName(userName)
		if user == nil && err == nil {
			// 删除redis中的缓存
			if err = cache.DelSessionInfo(session); err != nil {
				log.Error("Failed to delete session for cache, username=%s with err:", userName, err.Error())
			}
			if err = cache.DelUserInfo(userName); err != nil {
				log.Error("Failed to delete userInfo for cache, username=%s with err:", userName, err.Error())
			}
		} else {
			log.Error("Failed to delete userInfo in database, username=%s with err:", userName, err.Error())
		}
	}
	return nil
}
