// handlers_tcp.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"time"
)

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	log.Println("New connection from:", conn.RemoteAddr())
	data, err := io.ReadAll(conn)
	if err != nil {
		log.Println("Error reading:", err)
		return
	}
	log.Println("Received data:", string(data))
	var req map[string]interface{}
	err = json.Unmarshal(data, &req)
	if err != nil {
		log.Println("Error unmarshal:", err)
		return
	}
	action, ok := req["action"].(string)
	if !ok {
		sendTCPResponse(conn, map[string]interface{}{"status": "error", "message": "Invalid action"})
		return
	}

	switch action {
	case "check_connection":
		sendTCPResponse(conn, map[string]interface{}{"status": "success", "message": "Connection OK"})
	case "authenticate":
		keyStr, _ := req["key"].(string)
		hwid, _ := req["hwid"].(string)
		auth, msg := authenticateKey(keyStr, hwid)
		status := "error"
		if auth {
			status = "success"
		}
		sendTCPResponse(conn, map[string]interface{}{"status": status, "message": msg})
	case "log":
		keyStr, _ := req["key"].(string)
		hwid, _ := req["hwid"].(string)
		message, _ := req["message"].(string)
		addLog(keyStr, hwid, message)
		sendTCPResponse(conn, map[string]interface{}{"status": "success", "message": "Log added"})
	case "get_dll":
		dllData, err := ioutil.ReadFile("cheat.dll")
		if err != nil {
			sendTCPResponse(conn, map[string]interface{}{"status": "error", "message": "Failed to read DLL"})
			return
		}
		dllBase64 := base64.StdEncoding.EncodeToString(dllData)
		sendTCPResponse(conn, map[string]interface{}{"status": "success", "dll": dllBase64})
	case "ban_hwid":
		hwid, _ := req["hwid"].(string)
		banHWID(hwid, "", "Admin ban")
		sendTCPResponse(conn, map[string]interface{}{"status": "success", "message": "HWID banned"})
	default:
		sendTCPResponse(conn, map[string]interface{}{"status": "error", "message": "Unknown action"})
	}
}

func sendTCPResponse(conn net.Conn, resp map[string]interface{}) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Println("Error marshal:", err)
		return
	}
	conn.Write(data)
}

func authenticateKey(keyStr, hwid string) (bool, string) {
	keys, err := LoadKeys()
	if err != nil {
		return false, "Internal error"
	}
	idx := FindKeyIndex(keys, keyStr)
	if idx == -1 {
		return false, "Key not found"
	}
	k := &keys[idx]
	now := time.Now()
	if k.Banned {
		return false, "Key banned"
	}
	bans, _ := LoadBans()
	for _, b := range bans {
		if b.HWID == hwid {
			return false, "HWID banned"
		}
	}
	if k.BoundHWID == "" {
		k.BoundHWID = hwid
		k.ActivatedAt = &now
		if k.Duration > 0 {
			expires := now.Add(time.Duration(k.Duration) * time.Second)
			k.ExpiresAt = &expires
		}
	} else if k.BoundHWID != hwid {
		return false, "HWID mismatch"
	}
	if !k.Frozen && k.Duration > 0 && k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		return false, "Key expired"
	}
	k.LastUsed = &now
	SaveKeys(keys)
	return true, "Authentication successful"
}

func addLog(keyStr, hwid, message string) {
	logs, err := LoadLogs()
	if err != nil {
		log.Println(err)
		return
	}
	now := time.Now()
	newLog := LogEntry{
		ID:        len(logs) + 1, // Simple auto-increment
		Key:       keyStr,
		HWID:      hwid,
		Message:   message,
		Timestamp: now,
	}
	logs = append(logs, newLog)
	SaveLogs(logs)
}
