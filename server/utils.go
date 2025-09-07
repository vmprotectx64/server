// utils.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	keysMutex     sync.Mutex
	bansMutex     sync.Mutex
	logsMutex     sync.Mutex
	usersMutex    sync.Mutex
	sessionsMutex sync.Mutex

	// Секретный ключ для шифрования сессий (32 байта для AES-256)
	sessionSecret  = []byte("TekPLUAU2_DbHcFgM@EtC[RDOIQJArg;")
	activeSessions = make(map[string]*SessionData)
)

type Key struct {
	Key         string     `json:"key"`
	Duration    int64      `json:"duration"` // seconds, -1 for forever
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	BoundHWID   string     `json:"bound_hwid"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	Frozen      bool       `json:"frozen"`
	Banned      bool       `json:"banned"`
	BanReason   string     `json:"ban_reason"`
}

type Ban struct {
	HWID     string    `json:"hwid"`
	Key      string    `json:"key"`
	Reason   string    `json:"reason"`
	BannedAt time.Time `json:"banned_at"`
}

type LogEntry struct {
	ID        int       `json:"id"`
	Key       string    `json:"key"`
	HWID      string    `json:"hwid"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type User struct {
	Login    string   `json:"login"`
	Password string   `json:"password"` // bcrypt hash
	IPs      []string `json:"ips"`
}

type SessionData struct {
	Login     string    `json:"login"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	SessionID string    `json:"session_id"`
}

// Генерация случайного ID сессии
func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Printf("Error generating session ID: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// Шифрование данных сессии
func encryptSessionData(data []byte) (string, error) {
	block, err := aes.NewCipher(sessionSecret)
	if err != nil {
		return "", err
	}

	// Создаем случайный IV
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Шифруем
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Расшифровка данных сессии
func decryptSessionData(encryptedData string) ([]byte, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionSecret)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Создание безопасной сессии
func CreateSecureSession(login, ip string) (string, error) {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	// Очищаем старые сессии для этого пользователя
	cleanupUserSessions(login)

	sessionID := generateSessionID()
	if sessionID == "" {
		return "", errors.New("failed to generate session ID")
	}

	sessionData := &SessionData{
		Login:     login,
		IP:        ip,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 часа
		SessionID: sessionID,
	}

	// Сериализуем данные сессии
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}

	// Шифруем данные сессии
	encryptedSession, err := encryptSessionData(sessionBytes)
	if err != nil {
		return "", err
	}

	// Сохраняем сессию в памяти
	activeSessions[sessionID] = sessionData

	// Создаем токен: зашифрованные_данные.session_id
	token := encryptedSession + "." + sessionID

	return token, nil
}

// Валидация сессии
func ValidateSession(token, ip string) bool {
	if token == "" {
		return false
	}

	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	// Разделяем токен на зашифрованные данные и ID сессии
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	encryptedData := parts[0]
	sessionID := parts[1]

	// Проверяем, существует ли сессия в памяти
	sessionData, exists := activeSessions[sessionID]
	if !exists {
		return false
	}

	// Проверяем срок действия
	if time.Now().After(sessionData.ExpiresAt) {
		delete(activeSessions, sessionID)
		return false
	}

	// Расшифровываем и проверяем данные
	decryptedBytes, err := decryptSessionData(encryptedData)
	if err != nil {
		log.Printf("Error decrypting session: %v", err)
		return false
	}

	var decryptedSession SessionData
	err = json.Unmarshal(decryptedBytes, &decryptedSession)
	if err != nil {
		log.Printf("Error unmarshaling session: %v", err)
		return false
	}

	// Проверяем IP и login
	if decryptedSession.IP != ip || decryptedSession.Login != sessionData.Login {
		log.Printf("Session validation failed: IP mismatch or login mismatch")
		return false
	}

	// Проверяем, что пользователь все еще существует и IP разрешен
	return AuthenticateUserIP(decryptedSession.Login, ip)
}

// Вспомогательная функция для проверки IP пользователя без пароля
func AuthenticateUserIP(login, ip string) bool {
	users, err := LoadUsers()
	if err != nil {
		log.Printf("Error loading users: %v", err)
		return false
	}

	for _, user := range users {
		if user.Login == login {
			// Проверяем IP
			for _, allowedIP := range user.IPs {
				if ip == allowedIP || allowedIP == "127.0.0.1" {
					return true
				}
				if strings.Contains(ip, allowedIP) {
					return true
				}
			}
			return false
		}
	}
	return false
}

// Очистка старых сессий пользователя
func cleanupUserSessions(login string) {
	toDelete := []string{}
	for sessionID, sessionData := range activeSessions {
		if sessionData.Login == login || time.Now().After(sessionData.ExpiresAt) {
			toDelete = append(toDelete, sessionID)
		}
	}
	for _, sessionID := range toDelete {
		delete(activeSessions, sessionID)
	}
}

// Удаление конкретной сессии (для логаута)
func DestroySession(token string) {
	if token == "" {
		return
	}

	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return
	}

	sessionID := parts[1]
	delete(activeSessions, sessionID)
}

// Очистка всех истекших сессий (можно вызывать периодически)
func CleanupExpiredSessions() {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	toDelete := []string{}
	for sessionID, sessionData := range activeSessions {
		if time.Now().After(sessionData.ExpiresAt) {
			toDelete = append(toDelete, sessionID)
		}
	}

	for _, sessionID := range toDelete {
		delete(activeSessions, sessionID)
	}

	if len(toDelete) > 0 {
		log.Printf("Cleaned up %d expired sessions", len(toDelete))
	}
}

// Инициализация секретного ключа из переменной окружения или файла
func InitSessionSecret() {
	// Попробуем получить из переменной окружения
	if secret := os.Getenv("SESSION_SECRET"); secret != "" {
		hash := sha256.Sum256([]byte(secret))
		sessionSecret = hash[:]
		log.Println("Session secret loaded from environment variable")
		return
	}

	// Попробуем прочитать из файла
	if data, err := ioutil.ReadFile("session.key"); err == nil {
		if len(data) >= 32 {
			sessionSecret = data[:32]
			log.Println("Session secret loaded from session.key file")
			return
		}
	}

	// Генерируем новый ключ и сохраняем
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		log.Fatalf("Failed to generate session secret: %v", err)
	}

	sessionSecret = newSecret
	err := ioutil.WriteFile("session.key", newSecret, 0600)
	if err != nil {
		log.Printf("Warning: Failed to save session key to file: %v", err)
	} else {
		log.Println("New session secret generated and saved to session.key")
	}
}

func LoadKeys() ([]Key, error) {
	keysMutex.Lock()
	defer keysMutex.Unlock()
	data, err := ioutil.ReadFile("data/keys.json")
	if err != nil {
		if os.IsNotExist(err) {
			return []Key{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return []Key{}, nil
	}
	var keys []Key
	err = json.Unmarshal(data, &keys)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func SaveKeys(keys []Key) error {
	keysMutex.Lock()
	defer keysMutex.Unlock()
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile("data/keys.json", data, 0644)
}

func LoadBans() ([]Ban, error) {
	bansMutex.Lock()
	defer bansMutex.Unlock()
	data, err := ioutil.ReadFile("data/bans.json")
	if err != nil {
		if os.IsNotExist(err) {
			return []Ban{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return []Ban{}, nil
	}
	var bans []Ban
	err = json.Unmarshal(data, &bans)
	if err != nil {
		return nil, err
	}
	return bans, nil
}

func SaveBans(bans []Ban) error {
	bansMutex.Lock()
	defer bansMutex.Unlock()
	data, err := json.MarshalIndent(bans, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile("data/bans.json", data, 0644)
}

func LoadLogs() ([]LogEntry, error) {
	logsMutex.Lock()
	defer logsMutex.Unlock()
	data, err := ioutil.ReadFile("data/logs.json")
	if err != nil {
		if os.IsNotExist(err) {
			return []LogEntry{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return []LogEntry{}, nil
	}
	var logs []LogEntry
	err = json.Unmarshal(data, &logs)
	if err != nil {
		return nil, err
	}
	return logs, nil
}

func SaveLogs(logs []LogEntry) error {
	logsMutex.Lock()
	defer logsMutex.Unlock()
	data, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile("data/logs.json", data, 0644)
}

func LoadUsers() ([]User, error) {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	data, err := ioutil.ReadFile("data/users.json")
	if err != nil {
		if os.IsNotExist(err) {
			// Create default users if file doesn't exist
			defaultUsers := []User{
				{
					Login:    "sh1r0",
					Password: "$2a$15$qeWZD2ACA.farjea7E4JkeQCXJ2FcT987sLUdqZNJR/bMqTinmPHi",
					IPs:      []string{"104.28.254.34", "192.168.3.10", "127.0.0.1"},
				},
			}
			SaveUsers(defaultUsers)
			return defaultUsers, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return []User{}, nil
	}
	var users []User
	err = json.Unmarshal(data, &users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func SaveUsers(users []User) error {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile("data/users.json", data, 0644)
}

func AuthenticateUser(login, password, ip string) bool {
	users, err := LoadUsers()
	if err != nil {
		log.Printf("Error loading users: %v", err)
		return false
	}

	log.Printf("Authenticating user: %s with IP: %s", login, ip)

	for _, user := range users {
		if user.Login == login {
			log.Printf("Found user: %s", login)

			// Check password
			if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
				log.Printf("Password check failed for user: %s", login)
				return false
			}
			log.Printf("Password check passed for user: %s", login)

			// Check IP - исправленная логика
			ipAllowed := false
			for _, allowedIP := range user.IPs {
				log.Printf("Checking IP: %s against allowed: %s", ip, allowedIP)
				if ip == allowedIP || allowedIP == "127.0.0.1" {
					ipAllowed = true
					break
				}
				// Проверяем, содержится ли IP в разрешенном (для подсетей)
				if strings.Contains(ip, allowedIP) {
					ipAllowed = true
					break
				}
			}

			log.Printf("IP check result for user %s: %t", login, ipAllowed)
			return ipAllowed
		}
	}

	log.Printf("User not found: %s", login)
	return false
}

func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ip := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		log.Printf("Using X-Forwarded-For IP: %s", ip)
		return ip
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		log.Printf("Using X-Real-IP: %s", realIP)
		return realIP
	}

	// Fall back to RemoteAddr
	ip := strings.Split(r.RemoteAddr, ":")[0]
	log.Printf("Using RemoteAddr IP: %s", ip)
	return ip
}

// Helper to find key index by key string
func FindKeyIndex(keys []Key, keyStr string) int {
	for i, k := range keys {
		if k.Key == keyStr {
			return i
		}
	}
	return -1
}

// Helper to find ban index by HWID
func FindBanIndex(bans []Ban, hwid string) int {
	for i, b := range bans {
		if b.HWID == hwid {
			return i
		}
	}
	return -1
}

// Other utilities, e.g., for template functions
func TimeNow() time.Time {
	return time.Now()
}

func SubTime(a, b time.Time) time.Duration {
	return a.Sub(b)
}

func GtDuration(a, b time.Duration) bool {
	return a > b
}

// Периодическая очистка истекших сессий
func StartSessionCleanup() {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				CleanupExpiredSessions()
			}
		}
	}()
}
