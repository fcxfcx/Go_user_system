package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"user_system/config"
	"user_system/internal/service"
	"user_system/pkg/constant"
	"user_system/utils"
)

// Ping 健康检查
func Ping(c *gin.Context) {
	appConfig := config.GetGlobalConf().AppConfig
	confInfo, _ := json.MarshalIndent(appConfig, "", "  ")
	appInfo := fmt.Sprintf("app_name: %s\nversion: %s\n\n%s", appConfig.AppName, appConfig.Version,
		string(confInfo))
	c.String(http.StatusOK, appInfo)
}

// Register 注册
func Register(c *gin.Context) {
	req := &service.RegisterRequest{}
	rsp := &HttpResponse{}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Errorf("request json err %v", err)
		rsp.ResponseWithError(c, CodeBodyBindErr, err.Error())
		return
	}
	if err := service.Register(req); err != nil {
		rsp.ResponseWithError(c, CodeRegisterErr, err.Error())
		return
	}
	rsp.ResponseSuccess(c)
}

// Login 登录
func Login(c *gin.Context) {
	req := &service.LoginRequest{}
	rsp := &HttpResponse{}
	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Errorf("request json err %v", err)
		rsp.ResponseWithError(c, CodeBodyBindErr, err.Error())
		return
	}

	uuid := utils.Md5String(req.UserName + time.Now().GoString())
	ctx := context.WithValue(context.Background(), "uuid", uuid)
	log.Infof("loggin start,user:%s, password:%s", req.UserName, req.PassWord)
	session, err := service.Login(ctx, req)
	if err != nil {
		rsp.ResponseWithError(c, CodeLoginErr, err.Error())
		return
	}
	// 登陆成功，设置cookie
	c.SetCookie(constant.SessionKey, session, constant.CookieExpire, "/", "", false, true)
	rsp.ResponseSuccess(c)
}

// Logout 登出
func Logout(c *gin.Context) {
	session, _ := c.Cookie(constant.SessionKey)
	ctx := context.WithValue(context.Background(), constant.SessionKey, session)
	req := &service.LogoutRequest{}
	rsp := &HttpResponse{}
	err := c.ShouldBindJSON(req)
	if err != nil {
		log.Errorf("bind get logout request json err %v", err)
		rsp.ResponseWithError(c, CodeBodyBindErr, err.Error())
		return
	}
	uuid := utils.Md5String(req.UserName + time.Now().GoString())
	ctx = context.WithValue(ctx, "uuid", uuid)
	if err := service.Logout(ctx, req); err != nil {
		rsp.ResponseWithError(c, CodeLogoutErr, err.Error())
		return
	}
	// 登出成功，删除cookie
	c.SetCookie(constant.SessionKey, session, -1, "/", "", false, true)
	rsp.ResponseSuccess(c)
}

// Logoff 注销
func Logoff(c *gin.Context) {
	session, _ := c.Cookie(constant.SessionKey)
	ctx := context.WithValue(context.Background(), constant.SessionKey, session)
	req := &service.LogoffRequest{}
	rsp := &HttpResponse{}
	err := c.ShouldBindJSON(req)
	if err != nil {
		log.Errorf("bind get logoff request json err %v", err)
		rsp.ResponseWithError(c, CodeBodyBindErr, err.Error())
		return
	}
	uuid := utils.Md5String(req.UserName + time.Now().GoString())
	ctx = context.WithValue(ctx, "uuid", uuid)
	if err := service.Logoff(ctx, req); err != nil {
		rsp.ResponseWithError(c, CodeLogoffErr, err.Error())
		return
	}
	c.SetCookie(constant.SessionKey, session, -1, "/", "", false, true)
	rsp.ResponseSuccess(c)
}

// GetUserInfo 获取用户信息
func GetUserInfo(c *gin.Context) {
	userName := c.Query("username")
	session, _ := c.Cookie(constant.SessionKey)
	ctx := context.WithValue(context.Background(), constant.SessionKey, session)
	req := &service.GetUserInfoRequest{
		UserName: userName,
	}
	rsp := &HttpResponse{}
	uuid := utils.Md5String(req.UserName + time.Now().GoString())
	ctx = context.WithValue(ctx, "uuid", uuid)
	userInfo, err := service.GetUserInfo(ctx, req)
	if err != nil {
		rsp.ResponseWithError(c, CodeGetUserInfoErr, err.Error())
		return
	}
	rsp.ResponseWithData(c, userInfo)
}

// UpdateNickName 更新用户昵称
func UpdateNickName(c *gin.Context) {
	req := &service.UpdateNickNameRequest{}
	rsp := &HttpResponse{}
	err := c.ShouldBindJSON(req)
	if err != nil {
		log.Errorf("bind update user info request json err %v", err)
		rsp.ResponseWithError(c, CodeBodyBindErr, err.Error())
		return
	}
	session, _ := c.Cookie(constant.SessionKey)
	log.Infof("UpdateNickName|session=%s", session)
	ctx := context.WithValue(context.Background(), constant.SessionKey, session)
	uuid := utils.Md5String(req.UserName + time.Now().GoString())
	ctx = context.WithValue(ctx, "uuid", uuid)
	if err := service.UpdateUserNickName(ctx, req); err != nil {
		rsp.ResponseWithError(c, CodeUpdateUserInfoErr, err.Error())
		return
	}
	rsp.ResponseSuccess(c)
}

// UploadPic 用户上传头像
func UploadPic(c *gin.Context) {
	rsp := &HttpResponse{}
	username := c.Query("username")
	file, header, err := c.Request.FormFile("picture")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 1, "msg": "未选择文件"})
		return
	}
	defer file.Close()
	// 保存文件到本地
	imagePath, err := saveAvatarLocally(file, header, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 1, "msg": "上传文件失败"})
		return
	}

	session, _ := c.Cookie(constant.SessionKey)
	log.Infof("UploadUserPic|session=%s", session)

	ctx := context.WithValue(context.Background(), constant.SessionKey, session)
	uuid := utils.Md5String(username + time.Now().GoString())
	ctx = context.WithValue(ctx, "uuid", uuid)
	if err := service.UploadPic(ctx, username, imagePath); err != nil {
		rsp.ResponseWithError(c, CodeUploadPicErr, err.Error())
		return
	}
	rsp.ResponseSuccess(c)
}

// 保存用户头像到本地
func saveAvatarLocally(file multipart.File, header *multipart.FileHeader, username string) (string, error) {
	// 生成一个唯一的文件名
	filename := username + filepath.Ext(header.Filename)
	// 保存文件到指定目录
	localPath := filepath.Join("./web/static/images/userPic", filename)
	// 储存到数据库中的头像路径
	path := filepath.Join("/images/userPic", filename)
	out, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	_, err = io.Copy(out, file)
	if err != nil {
		return "", err
	}
	return path, nil
}
