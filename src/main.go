package main

import (
	"bufio"
	cryptorand "crypto/rand"
	"embed"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var content embed.FS

// User 用户结构
type User struct {
	Expire int64
	Index  int64 // 虚拟时间戳，用于排序
}

// Card 认证码结构
type Card struct {
	Days  int
	Index int64
}

// AuthSystem 认证系统
type AuthSystem struct {
	mu       sync.RWMutex
	users    map[string]*User
	cards    map[string]*Card
	logFile  *os.File
	logger   *log.Logger
	stopChan chan bool
}

var system *AuthSystem

func init() {
	var seed int64
	err := binary.Read(cryptorand.Reader, binary.LittleEndian, &seed)
	if err != nil {
		panic("failed to generate secure random seed")
	}
	rand.Seed(seed)
}

func main() {
	system = &AuthSystem{
		users:    make(map[string]*User),
		cards:    make(map[string]*Card),
		stopChan: make(chan bool),
	}

	// 打开日志文件
	var err error
	system.logFile, err = os.OpenFile("auth.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}
	defer system.logFile.Close()

	// 创建同时输出到控制台和文件的logger
	multiWriter := MultiWriter{
		writers: []Writer{
			os.Stdout,
			system.logFile,
		},
	}
	system.logger = log.New(multiWriter, "", log.Ldate|log.Ltime)

	// 加载数据
	system.loadUsers()
	system.loadCards()

	// 启动自动保存协程
	go system.autoSave()

	// 启动HTTP服务器
	go system.startHTTPServer()

	// 启动CLI
	system.startCLI()
}

// MultiWriter 多输出writer
type MultiWriter struct {
	writers []Writer
}

type Writer interface {
	Write([]byte) (int, error)
}

func (mw MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
	}
	return len(p), nil
}

// 加载用户数据
func (bs *AuthSystem) loadUsers() {
	file, err := os.Open("users.txt")
	if err != nil {
		if !os.IsNotExist(err) {
			bs.logger.Printf("读取用户文件失败: %v", err)
		}
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	index := int64(1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.ReplaceAll(line, "\r", "")
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		expire, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}

		bs.users[parts[0]] = &User{
			Expire: expire,
			Index:  index,
		}
		index++
	}
}

// 加载认证码数据
func (bs *AuthSystem) loadCards() {
	file, err := os.Open("cards.txt")
	if err != nil {
		if !os.IsNotExist(err) {
			bs.logger.Printf("读取认证码文件失败: %v", err)
		}
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	index := int64(1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.ReplaceAll(line, "\r", "")
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		days, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		bs.cards[parts[0]] = &Card{
			Days:  days,
			Index: index,
		}
		index++
	}
}

// 保存用户数据
func (bs *AuthSystem) saveUsers() error {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	// 转换为切片并排序
	type userEntry struct {
		name string
		user *User
	}
	var entries []userEntry
	for name, user := range bs.users {
		entries = append(entries, userEntry{name, user})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].user.Index < entries[j].user.Index
	})

	// 写入文件
	file, err := os.Create("users.txt")
	if err != nil {
		return err
	}
	defer file.Close()

	for _, entry := range entries {
		fmt.Fprintf(file, "%s %d\n", entry.name, entry.user.Expire)
	}
	fmt.Fprintf(file, "\n")
	return nil
}

// 保存认证码数据
func (bs *AuthSystem) saveCards() error {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	// 转换为切片并排序
	type cardEntry struct {
		code string
		card *Card
	}
	var entries []cardEntry
	for code, card := range bs.cards {
		entries = append(entries, cardEntry{code, card})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].card.Index < entries[j].card.Index
	})

	// 写入文件
	file, err := os.Create("cards.txt")
	if err != nil {
		return err
	}
	defer file.Close()

	for _, entry := range entries {
		fmt.Fprintf(file, "%s %d\n", entry.code, entry.card.Days)
	}
	fmt.Fprintf(file, "\n")
	return nil
}

// 自动保存
func (bs *AuthSystem) autoSave() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			bs.saveUsers()
			bs.saveCards()
		case <-bs.stopChan:
			return
		}
	}
}

// 验证用户名
func isValidUsername(username string) bool {
	if username == "" {
		return false
	}
	for _, r := range username {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') || r == '_') {
			return false
		}
	}
	return true
}

// 生成认证码
func generateCode() string {
	chars := "123456789abcdefghjkmnpqrstuvwxyz"
	code := make([]byte, 20)
	for i := 0; i < 20; i++ {
		code[i] = chars[rand.Intn(len(chars))]
	}
	return string(code)
}

// HTTP处理函数
func (bs *AuthSystem) authHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")

	if !isValidUsername(username) {
		w.Write([]byte("无效的用户名"))
		return
	}

	bs.mu.RLock()
	user, exists := bs.users[username]
	bs.mu.RUnlock()

	if !exists {
		w.Write([]byte("未认证用户"))
		return
	}

	now := time.Now().Unix()
	if user.Expire > now {
		w.Write([]byte("okay"))
		bs.logger.Printf("用户认证成功: %s", username)
	} else {
		expireTime := time.Unix(user.Expire, 0).Format("2006-01-02 15:04:05")
		w.Write([]byte(fmt.Sprintf("认证过期 (%s)", expireTime)))
	}
}

func (bs *AuthSystem) activeHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	code := r.URL.Query().Get("code")

	if !isValidUsername(username) {
		w.Write([]byte("无效的用户名"))
		return
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	card, exists := bs.cards[code]
	if !exists {
		w.Write([]byte("无效的认证码"))
		return
	}

	// 删除已使用的认证码
	delete(bs.cards, code)

	// 更新用户订阅
	now := time.Now().Unix()
	user, exists := bs.users[username]
	if !exists {
		user = &User{
			Expire: 0,
			Index:  now, // 使用当前时间戳作为虚拟时间戳
		}
		bs.users[username] = user
	}

	// 计算新的过期时间
	base := user.Expire
	if base < now {
		base = now
	}
	user.Expire = base + int64(card.Days*86400)

	expireTime := time.Unix(user.Expire, 0).Format("2006-01-02 15:04:05")
	w.Write([]byte(fmt.Sprintf("认证成功，有效期至: %s", expireTime)))
	bs.logger.Printf("认证成功: 用户=%s, 新过期时间=%s", username, expireTime)
}

func (bs *AuthSystem) indexHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := content.ReadFile("index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// 启动HTTP服务器
func (bs *AuthSystem) startHTTPServer() {
	http.HandleFunc("/auth", bs.authHandler)
	http.HandleFunc("/active", bs.activeHandler)
	http.HandleFunc("/", bs.indexHandler)

	bs.logger.Println("HTTP服务器启动在端口80")
	if err := http.ListenAndServe(":80", nil); err != nil {
		bs.logger.Printf("HTTP服务器启动失败: %v", err)
	}
}

// CLI处理
func (bs *AuthSystem) startCLI() {
	scanner := bufio.NewScanner(os.Stdin)
	bs.logger.Println("认证系统已启动，输入help查看帮助")

	for scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())
		bs.logger.Printf("命令: %s", input)

		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "create":
			if len(parts) == 3 {
				bs.createCards(parts[1], parts[2])
			} else if len(parts) == 1 {
				bs.logger.Println("用法: create <num> <exp>")
			} else {
				bs.logger.Println("参数错误，用法: create <num> <exp>")
			}
		case "stop":
			bs.logger.Println("正在保存数据并退出...")
			bs.saveUsers()
			bs.saveCards()
			close(bs.stopChan)
			os.Exit(0)
		case "help":
			bs.logger.Println("可用命令:")
			bs.logger.Println("  create <num> <exp> - 创建num张有效期为exp天的认证码")
			bs.logger.Println("  create - 显示create命令用法")
			bs.logger.Println("  stop - 保存全部文件并关闭")
			bs.logger.Println("  help - 显示此帮助信息")

		default:
			bs.logger.Println("未知命令，请输入help查看帮助")
		}
	}
}

// 创建认证码
func (bs *AuthSystem) createCards(cardNumStr, expStr string) {
	cardNum, err := strconv.Atoi(cardNumStr)
	if err != nil || cardNum <= 0 {
		bs.logger.Println("无效的认证码数量")
		return
	}

	exp, err := strconv.Atoi(expStr)
	if err != nil || exp <= 0 {
		bs.logger.Println("无效的有效期天数")
		return
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	now := time.Now().Unix()
	codes := []string{}
	for i := 0; i < cardNum; i++ {
		code := generateCode()
		bs.cards[code] = &Card{
			Days:  exp,
			Index: now + int64(i), // 使用递增的虚拟时间戳
		}
		codes = append(codes, code)
		bs.logger.Printf("创建认证码: %s (有效期%d天)", code, exp)
	}

	bs.logger.Printf("成功创建%d张认证码", cardNum)
}
