package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Конфигурация прокси
type ProxyConfig struct {
	HTTPAddr      string
	SOCKS5Addr    string
	ViaProxy      bool
	HideIP        bool
	AuthEnabled   bool
	Username      string
	Password      string
	CustomHeaders map[string]string
}

var config = ProxyConfig{
	HTTPAddr:      ":8080",
	SOCKS5Addr:    ":1080",
	ViaProxy:      true,
	HideIP:        true,
	AuthEnabled:   true,
	Username:      "kuzia",
	Password:      "Kdf241206.",
	CustomHeaders: make(map[string]string),
}

// Проверка аутентификации HTTP прокси
func checkHTTPAuth(r *http.Request) bool {
	if !config.AuthEnabled {
		return true
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}
	// Ожидаем: "Basic base64(username:password)"
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	encoded := strings.TrimPrefix(auth, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}
	return credentials[0] == config.Username && credentials[1] == config.Password
}

// Проверка аутентификации SOCKS5
func checkSOCKS5Auth(conn net.Conn, methods []byte) bool {
	if !config.AuthEnabled {
		// Разрешаем без аутентификации если она отключена
		return true
	}
	// Ищем метод "username/password" (0x02)
	hasUserAuth := false
	for _, m := range methods {
		if m == 2 {
			hasUserAuth = true
			break
		}
	}
	return hasUserAuth
}

// Обработка username/password аутентификации SOCKS5
func handleSOCKS5UserAuth(conn net.Conn) bool {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || buf[0] != 1 {
		log.Printf("[SOCKS5] Invalid auth request")
		return false
	}
	// buf[1] = username length
	usernameLen := int(buf[1])
	if n < 2+usernameLen+1 {
		log.Printf("[SOCKS5] Incomplete auth request")
		return false
	}
	username := string(buf[2 : 2+usernameLen])
	passwordLen := int(buf[2+usernameLen])
	if n < 2+usernameLen+1+passwordLen {
		log.Printf("[SOCKS5] Incomplete auth request")
		return false
	}
	password := string(buf[2+usernameLen+1 : 2+usernameLen+1+passwordLen])
	log.Printf("[SOCKS5] Auth attempt for user: %s", username)
	// Проверяем credentials
	if username == config.Username && password == config.Password {
		conn.Write([]byte{1, 0}) // Success
		log.Printf("[SOCKS5] Auth successful for: %s", username)
		return true
	}
	conn.Write([]byte{1, 1}) // Failure
	log.Printf("[SOCKS5] Auth failed for: %s", username)
	return false
}

// Инициализация стандартных заголовков для сокрытия местоположения
func initHeaders() {
	config.CustomHeaders["Accept-Encoding"] = "gzip, deflate, br"
	config.CustomHeaders["Accept-Language"] = "en-US,en;q=0.9"
	config.CustomHeaders["Cache-Control"] = "no-cache"
	config.CustomHeaders["Connection"] = "keep-alive"
	config.CustomHeaders["Sec-Ch-Ua"] = `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`
	config.CustomHeaders["Sec-Ch-Ua-Mobile"] = "?0"
	config.CustomHeaders["Sec-Ch-Ua-Platform"] = `"Windows"`
	config.CustomHeaders["Sec-Fetch-Dest"] = "document"
	config.CustomHeaders["Sec-Fetch-Mode"] = "navigate"
	config.CustomHeaders["Sec-Fetch-Site"] = "none"
	config.CustomHeaders["Sec-Fetch-User"] = "?1"
	config.CustomHeaders["Upgrade-Insecure-Requests"] = "1"
	config.CustomHeaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

// HTTP Handler - основной обработчик HTTP/HTTPS запросов
func httpProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HTTP] %s %s %s", r.Method, r.URL.String(), r.RemoteAddr)

	// Проверка аутентификации
	if config.AuthEnabled && !checkHTTPAuth(r) {
		log.Printf("[HTTP] Auth required for %s", r.RemoteAddr)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	// Удаляем заголовки, которые могут раскрыть реальное местоположение
	deleteHopByHopHeaders(r)

	// Добавляем кастомные заголовки для маскировки
	for k, v := range config.CustomHeaders {
		r.Header.Set(k, v)
	}

	// Если нужно скрыть IP, удаляем X-Forwarded-For
	if config.HideIP {
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Real-IP")
	}

	// Создаем HTTP клиент с потоковой передачей
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: false,
		},
		Timeout: 0, // Без таймаута для потоковой передачи
	}

	// Копируем тело запроса для потоковой передачи
	var bodyReader io.Reader
	if r.Body != nil {
		bodyReader = r.Body
	}
	defer r.Body.Close() // Safe even if nil (Close() on nil returns nil)

	// Создаем новый запрос к целевому серверу
	log.Printf("[HTTP] Forwarding to URL: %s", r.URL.String())
	req, err := http.NewRequest(r.Method, r.URL.String(), bodyReader)
	if err != nil {
		log.Printf("[HTTP] Error creating request: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Копируем заголовки
	for k, v := range r.Header {
		// Пропускаем hop-by-hop заголовки
		if isHopByHopHeader(k) {
			continue
		}
		req.Header[k] = v
	}

	// Добавляем Via заголовок если нужно
	if config.ViaProxy {
		req.Header.Set("Via", "1.1 proxy-server")
	}

	// Выполняем запрос к целевому серверу
	log.Printf("[HTTP] Sending request to target...")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[HTTP] Error forwarding request: %v", err)
		log.Printf("[HTTP] Request URL was: %s", r.URL.String())
		http.Error(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Удаляем hop-by-hop заголовки из ответа
	deleteHopByHopHeadersResponse(resp)

	// Копируем статус и заголовки ответа
	w.WriteHeader(resp.StatusCode)
	for k, v := range resp.Header {
		for _, val := range v {
			w.Header().Add(k, val) // Add preserves multi-value headers
		}
	}

	// Потоковая передача тела ответа
	io.Copy(w, resp.Body)
	log.Printf("[HTTP] Response: %d %s", resp.StatusCode, r.URL.String())
}

// Удаляет hop-by-hop заголовки из запроса
func deleteHopByHopHeaders(r *http.Request) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, h := range hopByHop {
		r.Header.Del(h)
	}
}

// Удаляет hop-by-hop заголовки из ответа
func deleteHopByHopHeadersResponse(resp *http.Response) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, h := range hopByHop {
		resp.Header.Del(h)
	}
}

// Проверяет является ли заголовок hop-by-hop
func isHopByHopHeader(name string) bool {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, h := range hopByHop {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// SOCKS5 обработчик
func socks5Proxy(conn net.Conn) {
	defer conn.Close()

	log.Printf("[SOCKS5] New connection from %s", conn.RemoteAddr())

	// Читаем версию SOCKS
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[SOCKS5] Error reading: %v", err)
		return
	}
	if n == 0 {
		log.Printf("[SOCKS5] Empty read")
		return
	}
	log.Printf("[SOCKS5] First byte: 0x%02x, data: %q", buf[0], string(buf[:n]))
	if buf[0] != 5 {
		log.Printf("[SOCKS5] Invalid version - expected 5, got %d", buf[0])
		return
	}

	// Получаем методы аутентификации
	numMethods := int(buf[1])
	methods := buf[2 : 2+numMethods]
	log.Printf("[SOCKS5] Auth methods: %v", methods)

	// Выбираем метод
	var selectedMethod byte
	if config.AuthEnabled {
		// Ищем username/password auth (0x02)
		hasUserAuth := false
		for _, m := range methods {
			if m == 2 {
				hasUserAuth = true
				break
			}
		}
		if !hasUserAuth {
			conn.Write([]byte{5, 0xFF}) // Нет подходящего метода
			return
		}
		selectedMethod = 2 // username/password
	} else {
		// Ищем без аутентификации (0x00)
		hasNoAuth := false
		for _, m := range methods {
			if m == 0 {
				hasNoAuth = true
				break
			}
		}
		if !hasNoAuth {
			conn.Write([]byte{5, 0xFF}) // Нет подходящего метода
			return
		}
		selectedMethod = 0 // без аутентификации
	}

	// Отправляем ответ о выборе метода
	conn.Write([]byte{5, selectedMethod})

	// Если выбран username/password auth, обрабатываем его
	if selectedMethod == 2 {
		if !handleSOCKS5UserAuth(conn) {
			return // Аутентификация не прошла
		}
	}

	// Читаем запрос
	n, err = conn.Read(buf)
	if err != nil {
		log.Printf("[SOCKS5] Error reading request: %v", err)
		return
	}

	if buf[0] != 5 {
		log.Printf("[SOCKS5] Invalid request version")
		return
	}

	// Парсим адрес
	var targetAddr string
	var targetPort uint16

	switch buf[3] {
	case 1: // IPv4
		if n < 10 {
			log.Printf("[SOCKS5] Invalid IPv4 request")
			return
		}
		ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
		targetPort = binary.BigEndian.Uint16(buf[8:10])
		targetAddr = fmt.Sprintf("%s:%d", ip, targetPort)

	case 3: // Доменное имя
		if n < 5 {
			log.Printf("[SOCKS5] Invalid domain request")
			return
		}
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			log.Printf("[SOCKS5] Incomplete domain request")
			return
		}
		domain := string(buf[5 : 5+domainLen])
		targetPort = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
		targetAddr = fmt.Sprintf("%s:%d", domain, targetPort)

	case 4: // IPv6
		if n < 22 {
			log.Printf("[SOCKS5] Invalid IPv6 request")
			return
		}
		ip := net.IP(buf[4:20])
		targetPort = binary.BigEndian.Uint16(buf[20:22])
		targetAddr = fmt.Sprintf("[%s]:%d", ip, targetPort)

	default:
		log.Printf("[SOCKS5] Unsupported address type: %d", buf[3])
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	log.Printf("[SOCKS5] Connecting to %s", targetAddr)

	// Подключаемся к целевому серверу
	var targetConn net.Conn
	if strings.Contains(targetAddr, ":") {
		// Убираем скобки для IPv6
		addr := targetAddr
		if strings.HasPrefix(addr, "[") {
			addr = addr[1:]
			if idx := strings.LastIndex(addr, "]"); idx != -1 {
				addr = addr[:idx]
			}
		}
		var err error
		targetConn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			log.Printf("[SOCKS5] Failed to connect to %s: %v", targetAddr, err)
			conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) // General failure
			return
		}
	} else {
		var err error
		targetConn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[SOCKS5] Failed to connect to %s: %v", targetAddr, err)
			conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) // General failure
			return
		}
	}
	defer targetConn.Close()

	// Отправляем ответ об успешном подключении в зависимости от типа адреса
	var reply []byte
	var addrType byte = buf[3]

	switch addrType {
	case 1: // IPv4 - 10 байт
		reply = make([]byte, 10)
		reply[0] = 5
		reply[1] = 0 // Success
		reply[2] = 0
		reply[3] = 1
		// Bind address:port (используем remote адрес прокси)
		localAddr := targetConn.LocalAddr().(*net.TCPAddr)
		copy(reply[4:8], localAddr.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(localAddr.Port))

	case 3: // Доменное имя - 7 + len(domain)
		domain := strings.Split(targetAddr, ":")[0]
		domainLen := len(domain)
		reply = make([]byte, 7+domainLen)
		reply[0] = 5
		reply[1] = 0 // Success
		reply[2] = 0
		reply[3] = 3
		reply[4] = byte(domainLen)
		copy(reply[5:5+domainLen], domain)
		port := targetConn.LocalAddr().(*net.TCPAddr).Port
		binary.BigEndian.PutUint16(reply[5+domainLen:7+domainLen], uint16(port))

	case 4: // IPv6 - 22 байта
		reply = make([]byte, 22)
		reply[0] = 5
		reply[1] = 0 // Success
		reply[2] = 0
		reply[3] = 4
		localAddr := targetConn.LocalAddr().(*net.TCPAddr)
		copy(reply[4:20], localAddr.IP.To16())
		binary.BigEndian.PutUint16(reply[20:22], uint16(localAddr.Port))
	}

	conn.Write(reply)
	log.Printf("[SOCKS5] Tunnel established to %s", targetAddr)

	// Потоковая передача данных в обе стороны
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(targetConn, conn)
		if err != nil && err != io.EOF {
			log.Printf("[SOCKS5] Error copying from client: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, targetConn)
		if err != nil && err != io.EOF {
			log.Printf("[SOCKS5] Error copying to client: %v", err)
		}
	}()

	wg.Wait()
	log.Printf("[SOCKS5] Connection closed: %s", targetAddr)
}

// Функция для установки CONNECT туннеля HTTPS
func handleHTTPSConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HTTPS] CONNECT %s from %s", r.Host, r.RemoteAddr)

	// Получаем целевой адрес
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	log.Printf("[HTTPS] Target host: %s", host)

	// Устанавливаем соединение с целевым сервером
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		log.Printf("[HTTPS] Failed to connect to %s: %v", host, err)
		http.Error(w, fmt.Sprintf("Failed to connect to %s", host), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Проверяем поддержку Hijack
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[HTTPS] Server does not support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[HTTPS] Failed to hijack connection: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Отправляем успешный ответ CONNECT - Critical: must be sent before streaming
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		log.Printf("[HTTPS] Failed to send CONNECT response: %v", err)
		conn.Close()
		return
	}
	log.Printf("[HTTPS] CONNECT tunnel established to %s", host)

	// Потоковая передача данных в обе стороны
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(targetConn, conn)
		if err != nil && err != io.EOF {
			log.Printf("[HTTPS] Error copying from client: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, targetConn)
		if err != nil && err != io.EOF {
			log.Printf("[HTTPS] Error copying to target: %v", err)
		}
	}()

	wg.Wait()
	conn.Close()
	log.Printf("[HTTPS] SSL connection closed: %s", host)
}

// SOCKS5 сервер
func startSOCKS5Server() {
	ln, err := net.Listen("tcp", config.SOCKS5Addr)
	if err != nil {
		log.Printf("[SOCKS5] Failed to start: %v", err)
		return
	}
	log.Printf("[SOCKS5] Server listening on %s", config.SOCKS5Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go socks5Proxy(conn)
	}
}

// customProxyHandler обрабатывает все запросы к прокси
type customProxyHandler struct{}

func (h *customProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[PROXY] %s %s %s", r.Method, r.URL.String(), r.RemoteAddr)
	log.Printf("[PROXY] AuthEnabled=%v, AuthHeader=%q", config.AuthEnabled, r.Header.Get("Proxy-Authorization"))

	if r.Method == http.MethodConnect {
		handleHTTPSConnect(w, r)
		return
	}

	// Для HTTP запросов добавляем схему если отсутствует
	urlStr := r.URL.String()
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
		r.URL, _ = url.Parse(urlStr)
	}

	httpProxyHandler(w, r)
}

func main() {
	initHeaders()

	// Запуск HTTP/HTTPS прокси
	go func() {
		log.Printf("[HTTP] Proxy server starting on %s", config.HTTPAddr)
		log.Printf("[HTTP] Hide IP: %v, Via Proxy: %v", config.HideIP, config.ViaProxy)
		if err := http.ListenAndServe(config.HTTPAddr, &customProxyHandler{}); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP] Server error: %v", err)
		}
	}()

	// Запуск SOCKS5 прокси
	go startSOCKS5Server()

	// Ожидание сигнала дляGraceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down proxy servers...")
}

// Утилита для парсинга URL
func parseProxyURL(proxyURL string) (string, string, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", "", err
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		switch u.Scheme {
		case "http":
			host += ":8080"
		case "socks5":
			host += ":1080"
		}
	}

	return u.Scheme, host, nil
}

// Пример использования:
// Установка прокси для HTTP клиента
func setProxyForHTTP(client *http.Client, proxyURL string) error {
	scheme, host, err := parseProxyURL(proxyURL)
	if err != nil {
		return err
	}

	proxy, err := url.Parse(fmt.Sprintf("%s://%s", scheme, host))
	if err != nil {
		return err
	}

	client.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}

	return nil
}
