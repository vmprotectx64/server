// handlers_http.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

var tpl *template.Template

func init() {
	tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"timeNow": TimeNow,
		"subTime": SubTime,
		"gt":      GtDuration,
		"printf":  fmt.Sprintf,
		"atoi":    func(s string) int { i, _ := strconv.Atoi(s); return i },
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"formatDuration": func(d time.Duration) string {
			if d <= 0 {
				return "Expired"
			}

			totalMinutes := int(d.Minutes())
			days := totalMinutes / (24 * 60)
			hours := (totalMinutes % (24 * 60)) / 60
			minutes := totalMinutes % 60

			if days > 0 {
				return fmt.Sprintf("%dd %dh", days, hours)
			}
			if hours > 0 {
				return fmt.Sprintf("%dh %dm", hours, minutes)
			}
			if minutes > 0 {
				return fmt.Sprintf("%dm", minutes)
			}
			return "< 1m"
		},
		"timeUntilExpiry": func(expiresAt *time.Time) time.Duration {
			if expiresAt == nil {
				return 0
			}
			remaining := expiresAt.Sub(time.Now())
			if remaining < 0 {
				return 0
			}
			return remaining
		},
	}).ParseGlob("templates/*.html"))
}

func httpHandlers() {
	// Инициализируем систему безопасных сессий
	InitSessionSecret()
	StartSessionCleanup()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/keys", authMiddleware(keysHandler))
	http.HandleFunc("/keys/create", authMiddleware(createKeyHandler))
	http.HandleFunc("/keys/action", authMiddleware(keyActionHandler))
	http.HandleFunc("/bans", authMiddleware(bansHandler))
	http.HandleFunc("/bans/unban", authMiddleware(unbanHandler))
	http.HandleFunc("/logs", authMiddleware(logsHandler))
	http.HandleFunc("/logs/ban", authMiddleware(logBanHandler))

	// API for client actions via HTTP POST (не требует авторизации)
	http.HandleFunc("/api", apiHandler)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_session")
		if err != nil || !ValidateSession(cookie.Value, GetClientIP(r)) {
			log.Printf("Authentication failed, redirecting to login. Error: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err != nil || !ValidateSession(cookie.Value, GetClientIP(r)) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Показываем форму логина
		html := `<!DOCTYPE html>
<html lang="ru" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Login - Admin Panel</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h1>Admin Panel Login</h1>
            <form method="post" action="/login">
                <div class="form-group">
                    <input type="text" name="login" placeholder="Login" required class="input-sm">
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required class="input-sm">
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
    </div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(html))
		return
	}

	if r.Method == http.MethodPost {
		// Парсим форму
		err := r.ParseForm()
		if err != nil {
			log.Printf("Error parsing form: %v", err)
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		login := r.FormValue("login")
		password := r.FormValue("password")
		clientIP := GetClientIP(r)

		log.Printf("Login attempt: login=%s, ip=%s", login, clientIP)

		if login == "" || password == "" {
			log.Println("Empty login or password")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			errorHtml := getLoginFormWithError("Login and password are required", login)
			w.Write([]byte(errorHtml))
			return
		}

		if AuthenticateUser(login, password, clientIP) {
			log.Printf("Authentication successful for user: %s", login)

			// Создаем безопасную сессию
			sessionToken, err := CreateSecureSession(login, clientIP)
			if err != nil {
				log.Printf("Error creating session: %v", err)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				errorHtml := getLoginFormWithError("Error creating session", login)
				w.Write([]byte(errorHtml))
				return
			}

			cookie := &http.Cookie{
				Name:     "admin_session",
				Value:    sessionToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   false, // Установите true если используете HTTPS
				MaxAge:   86400, // 24 часа
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, cookie)

			log.Printf("Secure session created, redirecting to /keys")
			http.Redirect(w, r, "/keys", http.StatusSeeOther)
		} else {
			log.Printf("Authentication failed for user: %s, ip: %s", login, clientIP)

			// Добавляем небольшую задержку для защиты от брute force
			time.Sleep(1 * time.Second)

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			errorHtml := getLoginFormWithError("Invalid credentials or IP not allowed", login)
			w.Write([]byte(errorHtml))
		}
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Вспомогательная функция для генерации формы с ошибкой
func getLoginFormWithError(errorMsg, login string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Login - Admin Panel</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h1>Admin Panel Login</h1>
            <div style="color: #d9534f; margin-bottom: 15px; text-align: center;">%s</div>
            <form method="post" action="/login">
                <div class="form-group">
                    <input type="text" name="login" placeholder="Login" required class="input-sm" value="%s">
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required class="input-sm">
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
    </div>
</body>
</html>`, errorMsg, login)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем токен сессии и уничтожаем его
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		DestroySession(cookie.Value)
	}

	// Удаляем куки
	cookie = &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func keysHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := LoadKeys()
	if err != nil {
		log.Printf("Error loading keys: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Фильтруем ключи, убираем истекшие неактивированные ключи из отображения
	var validKeys []Key
	for _, key := range keys {
		// Показываем ключ если:
		// - он не активирован (ActivatedAt == nil)
		// - он активирован и не истек (или заморожен, или навсегда)
		// - он активирован и истек, но мы все равно показываем для управления
		if key.ActivatedAt == nil {
			validKeys = append(validKeys, key)
		} else {
			// Ключ активирован - показываем всегда
			validKeys = append(validKeys, key)
		}
	}

	data := struct {
		Keys []Key
	}{
		Keys: validKeys,
	}

	err = tpl.ExecuteTemplate(w, "keys.html", data)
	if err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func createKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	durationStr := r.FormValue("duration")
	var duration int64
	switch durationStr {
	case "hour":
		duration = 3600
	case "day":
		duration = 86400
	case "week":
		duration = 604800
	case "month":
		duration = 2592000
	case "year":
		duration = 31536000
	case "forever":
		duration = -1
	default:
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}
	keyStr := generateRandomKey(32)
	newKey := Key{
		Key:      keyStr,
		Duration: duration,
	}
	keys, err := LoadKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	keys = append(keys, newKey)
	err = SaveKeys(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func keyActionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keyStr := r.FormValue("key")
	action := r.FormValue("action")
	keys, err := LoadKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idx := FindKeyIndex(keys, keyStr)
	if idx == -1 {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}
	k := &keys[idx]
	switch action {
	case "freeze":
		k.Frozen = !k.Frozen
	case "ban":
		reason := r.FormValue("reason")
		k.Banned = true
		k.BanReason = reason
		if k.BoundHWID != "" {
			banHWID(k.BoundHWID, keyStr, reason)
		}
	case "delete":
		keys = append(keys[:idx], keys[idx+1:]...)
	case "reset_hwid":
		k.BoundHWID = ""
		k.ActivatedAt = nil
		k.ExpiresAt = nil
		k.LastUsed = nil
	case "extend":
		extendStr := r.FormValue("extend_duration")
		var extend int64
		switch extendStr {
		case "hour":
			extend = 3600
		case "day":
			extend = 86400
		case "week":
			extend = 604800
		case "month":
			extend = 2592000
		case "year":
			extend = 31536000
		}
		if k.Duration > 0 {
			k.Duration += extend
			if k.ExpiresAt != nil {
				newExpires := k.ExpiresAt.Add(time.Duration(extend) * time.Second)
				k.ExpiresAt = &newExpires
			} else if k.ActivatedAt != nil {
				newExpires := k.ActivatedAt.Add(time.Duration(k.Duration) * time.Second)
				k.ExpiresAt = &newExpires
			}
		}
	}
	err = SaveKeys(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func bansHandler(w http.ResponseWriter, r *http.Request) {
	bans, err := LoadBans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Bans []Ban
	}{
		Bans: bans,
	}
	tpl.ExecuteTemplate(w, "bans.html", data)
}

func unbanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hwid := r.FormValue("hwid")
	keyStr := r.FormValue("key")
	bans, err := LoadBans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idx := FindBanIndex(bans, hwid)
	if idx != -1 {
		bans = append(bans[:idx], bans[idx+1:]...)
		err = SaveBans(bans)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Unban key if exists
	keys, err := LoadKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	kIdx := FindKeyIndex(keys, keyStr)
	if kIdx != -1 {
		keys[kIdx].Banned = false
		keys[kIdx].BanReason = ""
		SaveKeys(keys)
	}
	http.Redirect(w, r, "/bans", http.StatusSeeOther)
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	logs, err := LoadLogs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Logs []LogEntry
	}{
		Logs: logs,
	}
	tpl.ExecuteTemplate(w, "logs.html", data)
}

func logBanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keyStr := r.FormValue("key")
	hwid := r.FormValue("hwid")
	reason := r.FormValue("reason")
	banHWID(hwid, keyStr, reason)
	keys, err := LoadKeys()
	if err == nil {
		idx := FindKeyIndex(keys, keyStr)
		if idx != -1 {
			keys[idx].Banned = true
			keys[idx].BanReason = reason
			SaveKeys(keys)
		}
	}
	http.Redirect(w, r, "/logs", http.StatusSeeOther)
}

func generateRandomKey(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req map[string]interface{}
	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action, ok := req["action"].(string)
	if !ok {
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Invalid action"})
		return
	}

	switch action {
	case "check_connection":
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "message": "Connection OK"})
	case "authenticate":
		keyStr, _ := req["key"].(string)
		hwid, _ := req["hwid"].(string)
		auth, msg := authenticateKey(keyStr, hwid)
		status := "error"
		if auth {
			status = "success"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": status, "message": msg})
	case "log":
		keyStr, _ := req["key"].(string)
		hwid, _ := req["hwid"].(string)
		message, _ := req["message"].(string)
		addLog(keyStr, hwid, message)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "message": "Log added"})
	case "get_dll":
		dllData, err := ioutil.ReadFile("cheat.dll")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Failed to read DLL"})
			return
		}
		dllBase64 := base64.StdEncoding.EncodeToString(dllData)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "dll": dllBase64})
	case "ban_hwid":
		hwid, _ := req["hwid"].(string)
		banHWID(hwid, "", "Admin ban")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "message": "HWID banned"})
	default:
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Unknown action"})
	}
}

func banHWID(hwid, keyStr, reason string) {
	bans, err := LoadBans()
	if err != nil {
		log.Println(err)
		return
	}
	idx := FindBanIndex(bans, hwid)
	now := time.Now()
	if idx == -1 {
		bans = append(bans, Ban{HWID: hwid, Key: keyStr, Reason: reason, BannedAt: now})
	} else {
		bans[idx].Reason = reason
		bans[idx].BannedAt = now
		bans[idx].Key = keyStr
	}
	SaveBans(bans)
}
