package util

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"

	log "github.com/inconshreveable/log15"
)

//GetCurrentDirectory 获取当前路径
func GetCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Error("Get filepath failed", "err", err)
		return ""
	}
	return strings.Replace(dir, "\\", "/", -1)
}

//GetHomeDir 获取当前用户home目录
func GetHomeDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir, nil
}
