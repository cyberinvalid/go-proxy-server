package main

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// ResponseOverride конфигурация для подмены ответа
type ResponseOverride struct {
	Name           string            `json:"name"`             // Имя правила для логов
	Method         string            `json:"method"`           // HTTP метод (* для любого)
	URLPattern     string            `json:"url_pattern"`      // Паттерн URL (поддерживает regex)
	IsRegex        bool              `json:"is_regex"`         // Использовать regex для паттерна
	StatusCode     int               `json:"status_code"`      // HTTP статус код
	Headers        map[string]string `json:"headers"`          // Заголовки ответа
	BodyFile       string            `json:"body_file"`        // Путь к файлу с телом ответа
	BodyText       string            `json:"body_text"`        // Текст ответа (альтернатива файлу)
	Enabled        bool              `json:"enabled"`          // Включено ли правило
	TriggerAfter   int               `json:"trigger_after"`    // После скольких запросов срабатывать (0 = сразу)
	MaxTriggers    int               `json:"max_triggers"`     // Максимальное количество срабатываний (-1 = бесконечно)
	ResetAfter     int               `json:"reset_after"`      // Сброс счетчика через N запросов (0 = не сбрасывать)
	compiledRegex  *regexp.Regexp    // Скомпилированный regex (не сериализуется)
	requestCount   int               // Счетчик запросов (не сериализуется)
	triggerCount   int               // Счетчик срабатываний (не сериализуется)
	mutex          sync.Mutex        // Мьютекс для безопасности (не сериализуется)
}

// Config конфигурация всех подмен
type Config struct {
	Overrides []ResponseOverride `json:"overrides"`
}

// LogSettings настройки логирования
type LogSettings struct {
	ShowRequestBody  bool
	ShowResponseBody bool
	BodyLogMode      string // "full", "truncate", "none", "json_full"
	MaxLogLength     int
}

var config Config
var logSettings LogSettings

func main() {
	// Получаем целевой хост из переменной окружения
	targetHost := os.Getenv("PROXY_TARGET")
	if targetHost == "" {
		targetHost = "https://test.yandex.net" // значение по умолчанию
	}

	// Получаем порт для локального сервера
	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "8080" // порт по умолчанию
	}

	// Настраиваем логирование
	setupLogSettings()

	// Загружаем конфигурацию подмен
	configFile := os.Getenv("OVERRIDE_CONFIG")
	if configFile == "" {
		configFile = "overrides.json"
	}
	loadConfig(configFile)

	// Парсим URL целевого хоста
	targetURL, err := url.Parse(targetHost)
	if err != nil {
		log.Fatalf("Ошибка парсинга целевого URL: %v", err)
	}

	// Создаем обработчик для всех запросов
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxyRequest(w, r, targetURL)
	})

	// Добавляем обработчик для просмотра статистики
	http.HandleFunc("/_proxy_stats", func(w http.ResponseWriter, r *http.Request) {
		showStats(w, r)
	})

	log.Printf("Прокси сервер запущен на http://127.0.0.1:%s", port)
	log.Printf("Проксирование запросов на: %s", targetHost)
	log.Printf("Конфигурация подмен: %s", configFile)
	log.Printf("Активных правил подмены: %d", countActiveOverrides())
	log.Printf("Статистика доступна на: http://127.0.0.1:%s/_proxy_stats", port)
	printLogSettings()

	if targetURL.Path != "" && targetURL.Path != "/" {
		log.Printf("Базовый path: %s", targetURL.Path)
	}

	// Запускаем сервер
	err = http.ListenAndServe("127.0.0.1:"+port, nil)
	if err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}

func setupLogSettings() {
	// Настройки логирования body
	logSettings.ShowRequestBody = os.Getenv("LOG_REQUEST_BODY") != "false"
	logSettings.ShowResponseBody = os.Getenv("LOG_RESPONSE_BODY") != "false"
	
	// Режим логирования body
	logSettings.BodyLogMode = strings.ToLower(os.Getenv("BODY_LOG_MODE"))
	if logSettings.BodyLogMode == "" {
		logSettings.BodyLogMode = "json_full" // по умолчанию
	}

	// Максимальная длина для truncate режима
	logSettings.MaxLogLength = 2000
	if maxLen := os.Getenv("MAX_LOG_LENGTH"); maxLen != "" {
		if parsed, err := strconv.Atoi(maxLen); err == nil && parsed > 0 {
			logSettings.MaxLogLength = parsed
		}
	}
}

func printLogSettings() {
	log.Printf("📋 Настройки логирования:")
	log.Printf("   Request Body: %v", logSettings.ShowRequestBody)
	log.Printf("   Response Body: %v", logSettings.ShowResponseBody)
	log.Printf("   Body Log Mode: %s", logSettings.BodyLogMode)
	if logSettings.BodyLogMode == "truncate" {
		log.Printf("   Max Log Length: %d", logSettings.MaxLogLength)
	}
	log.Printf("")
	log.Printf("💡 Доступные режимы BODY_LOG_MODE:")
	log.Printf("   - 'full' - показать все body полностью")
	log.Printf("   - 'truncate' - обрезать длинные body")
	log.Printf("   - 'json_full' - JSON полностью, остальное обрезать (по умолчанию)")
	log.Printf("   - 'none' - не показывать body")
	log.Printf("")
}

func loadConfig(configFile string) {
	// Создаем пример конфигурации если файл не существует
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		createExampleConfig(configFile)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("⚠️  Не удалось прочитать конфигурацию: %v", err)
		return
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Printf("⚠️  Ошибка парсинга конфигурации: %v", err)
		return
	}

	// Компилируем regex паттерны и инициализируем счетчики
	for i := range config.Overrides {
		override := &config.Overrides[i]
		if override.IsRegex {
			compiled, err := regexp.Compile(override.URLPattern)
			if err != nil {
				log.Printf("⚠️  Ошибка компиляции regex '%s': %v", override.URLPattern, err)
				override.Enabled = false
			} else {
				override.compiledRegex = compiled
			}
		}
		// Инициализируем счетчики
		override.requestCount = 0
		override.triggerCount = 0
	}

	log.Printf("✅ Загружена конфигурация из %s", configFile)
}

func createExampleConfig(configFile string) {
	exampleConfig := Config{
		Overrides: []ResponseOverride{
			{
				Name:        "Yandex bindings - срабатывает после 3 запросов",
				Method:      "*",
				URLPattern:  "/bindings",
				IsRegex:     false,
				StatusCode:  200,
				TriggerAfter: 3,
				MaxTriggers: 2,
				ResetAfter:  10,
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-Custom":     "overridden-after-3-requests",
				},
				BodyFile: "responses/bindings.json",
				Enabled:  true,
			},
			{
				Name:        "API users - мгновенная подмена",
				Method:      "GET",
				URLPattern:  `/api/users/\d+`,
				IsRegex:     true,
				StatusCode:  200,
				TriggerAfter: 0, // срабатывает сразу
				MaxTriggers: -1, // бесконечно
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				BodyText: `{"id": 123, "name": "Mock User", "email": "mock@example.com", "mocked": true}`,
				Enabled:  false,
			},
			{
				Name:        "Error simulation - после 5 запросов",
				Method:      "POST",
				URLPattern:  "/api/submit",
				IsRegex:     false,
				StatusCode:  500,
				TriggerAfter: 5,
				MaxTriggers: 1, // только один раз
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				BodyText: `{"error": "Simulated server error after 5 requests", "code": "MOCK_ERROR"}`,
				Enabled:  false,
			},
		},
	}

	data, _ := json.MarshalIndent(exampleConfig, "", "  ")
	err := os.WriteFile(configFile, data, 0644)
	if err != nil {
		log.Printf("⚠️  Не удалось создать пример конфигурации: %v", err)
	} else {
		log.Printf("📝 Создан пример конфигурации: %s", configFile)
		
		// Создаем директорию для файлов ответов
		os.MkdirAll("responses", 0755)
		
		// Создаем пример файла ответа
		exampleResponse := map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"bindings": []map[string]interface{}{
					{"id": 1, "name": "binding1", "type": "primary"},
					{"id": 2, "name": "binding2", "type": "secondary"},
					{"id": 3, "name": "binding3", "type": "primary"},
				},
				"total": 3,
			},
			"message": "This is a mocked response from file (triggered after N requests)",
			"triggered_at": "auto-generated",
		}
		responseData, _ := json.MarshalIndent(exampleResponse, "", "  ")
		os.WriteFile("responses/bindings.json", responseData, 0644)
		log.Printf("📝 Создан пример ответа: responses/bindings.json")
	}
}

func countActiveOverrides() int {
	count := 0
	for _, override := range config.Overrides {
		if override.Enabled {
			count++
		}
	}
	return count
}

func findMatchingOverride(method, urlPath string) *ResponseOverride {
	for i := range config.Overrides {
		override := &config.Overrides[i]
		if !override.Enabled {
			continue
		}

		// Проверяем метод
		if override.Method != "*" && !strings.EqualFold(override.Method, method) {
			continue
		}

		// Проверяем URL
		var matches bool
		if override.IsRegex {
			matches = override.compiledRegex != nil && override.compiledRegex.MatchString(urlPath)
		} else {
			matches = strings.Contains(urlPath, override.URLPattern)
		}

		if matches {
			override.mutex.Lock()
			override.requestCount++
			
			// Проверяем, нужно ли сбросить счетчики
			if override.ResetAfter > 0 && override.requestCount >= override.ResetAfter {
				log.Printf("🔄 Сброс счетчиков для правила '%s' (достигнуто %d запросов)", 
					override.Name, override.ResetAfter)
				override.requestCount = 0
				override.triggerCount = 0
				override.mutex.Unlock()
				continue
			}

			// Проверяем, достигли ли порога срабатывания
			shouldTrigger := override.requestCount > override.TriggerAfter

			// Проверяем лимит срабатываний
			if override.MaxTriggers > 0 && override.triggerCount >= override.MaxTriggers {
				shouldTrigger = false
			}

			if shouldTrigger {
				override.triggerCount++
				log.Printf("📊 Правило '%s': запрос %d, срабатывание %d", 
					override.Name, override.requestCount, override.triggerCount)
				override.mutex.Unlock()
				return override
			} else {
				log.Printf("📊 Правило '%s': запрос %d (нужно %d для срабатывания)", 
					override.Name, override.requestCount, override.TriggerAfter+1)
				override.mutex.Unlock()
			}
		}
	}
	return nil
}

func showStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	stats := make([]map[string]interface{}, 0, len(config.Overrides))
	
	for _, override := range config.Overrides {
		override.mutex.Lock()
		stat := map[string]interface{}{
			"name":          override.Name,
			"enabled":       override.Enabled,
			"url_pattern":   override.URLPattern,
			"method":        override.Method,
			"trigger_after": override.TriggerAfter,
			"max_triggers":  override.MaxTriggers,
			"reset_after":   override.ResetAfter,
			"request_count": override.requestCount,
			"trigger_count": override.triggerCount,
		}
		override.mutex.Unlock()
		stats = append(stats, stat)
	}
	
	response := map[string]interface{}{
		"overrides": stats,
		"total_rules": len(config.Overrides),
		"active_rules": countActiveOverrides(),
		"log_settings": map[string]interface{}{
			"show_request_body":  logSettings.ShowRequestBody,
			"show_response_body": logSettings.ShowResponseBody,
			"body_log_mode":      logSettings.BodyLogMode,
			"max_log_length":     logSettings.MaxLogLength,
		},
	}
	
	json.NewEncoder(w).Encode(response)
}

func proxyRequest(w http.ResponseWriter, r *http.Request, targetURL *url.URL) {
	// Пропускаем внутренние эндпоинты
	if strings.HasPrefix(r.URL.Path, "/_proxy") {
		return
	}

	// Объединяем базовый path из targetURL с path из запроса
	combinedPath := path.Join(targetURL.Path, r.URL.Path)
	
	// path.Join убирает trailing slash, восстанавливаем если нужно
	if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(combinedPath, "/") {
		combinedPath += "/"
	}

	// Создаем новый URL для проксирования
	proxyURL := &url.URL{
		Scheme:   targetURL.Scheme,
		Host:     targetURL.Host,
		Path:     combinedPath,
		RawQuery: r.URL.RawQuery,
	}

	log.Printf("🔄 %s %s -> %s", r.Method, r.URL.String(), proxyURL.String())

	// Проверяем, есть ли подмена для этого запроса
	if override := findMatchingOverride(r.Method, r.URL.Path); override != nil {
		log.Printf("🎭 Применяем подмену: %s", override.Name)
		handleOverride(w, r, override)
		return
	}

	// Логируем тело входящего запроса
	var requestBody []byte
	if r.Body != nil {
		requestBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		
		if len(requestBody) > 0 && logSettings.ShowRequestBody {
			logBody("📤 Request Body", requestBody, r.Header.Get("Content-Type"), r.Header)
		}
	}

	// Создаем новый HTTP запрос
	proxyReq, err := http.NewRequest(r.Method, proxyURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Ошибка создания запроса", http.StatusInternalServerError)
		log.Printf("❌ Ошибка создания запроса: %v", err)
		return
	}

	// Копируем все заголовки из оригинального запроса
	copyHeaders(proxyReq.Header, r.Header)

	// Устанавливаем правильный Host заголовок
	proxyReq.Host = targetURL.Host

	// Выполняем запрос
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Ошибка выполнения запроса", http.StatusBadGateway)
		log.Printf("❌ Ошибка выполнения запроса: %v", err)
		return
	}
	defer resp.Body.Close()

	// Читаем тело ответа для логирования
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Ошибка чтения ответа", http.StatusInternalServerError)
		log.Printf("❌ Ошибка чтения тела ответа: %v", err)
		return
	}

	// Логируем статус и заголовки ответа
	log.Printf("📥 Response Status: %d %s", resp.StatusCode, resp.Status)
	
	contentType := resp.Header.Get("Content-Type")
	contentEncoding := resp.Header.Get("Content-Encoding")
	
	if contentType != "" {
		log.Printf("📥 Response Content-Type: %s", contentType)
	}
	if contentEncoding != "" {
		log.Printf("📥 Response Content-Encoding: %s", contentEncoding)
	}

	// Логируем тело ответа
	if len(responseBody) > 0 && logSettings.ShowResponseBody {
		logBody("📥 Response Body", responseBody, contentType, resp.Header)
	}

	// Копируем заголовки ответа
	copyHeaders(w.Header(), resp.Header)

	// Устанавливаем статус код
	w.WriteHeader(resp.StatusCode)

	// Отправляем тело ответа клиенту
	_, err = w.Write(responseBody)
	if err != nil {
		log.Printf("❌ Ошибка отправки ответа клиенту: %v", err)
	}

	log.Printf("✅ Запрос завершен\n")
}

func handleOverride(w http.ResponseWriter, r *http.Request, override *ResponseOverride) {
	// Устанавливаем заголовки
	for key, value := range override.Headers {
		w.Header().Set(key, value)
	}

	// Получаем тело ответа
	var responseBody []byte
	var err error

	if override.BodyFile != "" {
		// Читаем из файла
		responseBody, err = os.ReadFile(override.BodyFile)
		if err != nil {
			log.Printf("❌ Ошибка чтения файла %s: %v", override.BodyFile, err)
			http.Error(w, "Ошибка чтения файла подмены", http.StatusInternalServerError)
			return
		}
		log.Printf("📂 Загружен ответ из файла: %s (%d bytes)", override.BodyFile, len(responseBody))
	} else if override.BodyText != "" {
		// Используем текст
		responseBody = []byte(override.BodyText)
		log.Printf("📝 Использован текст ответа (%d bytes)", len(responseBody))
	}

	// Устанавливаем Content-Length если есть тело
	if len(responseBody) > 0 {
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	}

	// Отправляем статус код
	w.WriteHeader(override.StatusCode)

	// Отправляем тело
	if len(responseBody) > 0 {
		_, err = w.Write(responseBody)
		if err != nil {
			log.Printf("❌ Ошибка отправки подменного ответа: %v", err)
		}
	}

	// Логируем подменный ответ
	log.Printf("🎭 Отправлен подменный ответ:")
	log.Printf("   Status: %d", override.StatusCode)
	log.Printf("   Headers: %v", override.Headers)
	
	if len(responseBody) > 0 && logSettings.ShowResponseBody {
		contentType := override.Headers["Content-Type"]
		logBody("   Body", responseBody, contentType, nil)
	}

	log.Printf("✅ Подмена завершена\n")
}

// logBody логирует тело запроса/ответа с учетом настроек
func logBody(prefix string, body []byte, contentType string, headers http.Header) {
	if len(body) == 0 {
		log.Printf("%s: [Empty]", prefix)
		return
	}

	// Проверяем режим логирования
	switch logSettings.BodyLogMode {
	case "none":
		log.Printf("%s: [Hidden by BODY_LOG_MODE=none]", prefix)
		return
	case "full":
		logBodyFull(prefix, body, contentType, headers)
		return
	case "truncate":
		logBodyTruncated(prefix, body, contentType, headers)
		return
	case "json_full":
		logBodyJSONSmart(prefix, body, contentType, headers)
		return
	default:
		log.Printf("%s: [Unknown BODY_LOG_MODE: %s]", prefix, logSettings.BodyLogMode)
		return
	}
}

// logBodyFull показывает body полностью
func logBodyFull(prefix string, body []byte, contentType string, headers http.Header) {
	if len(body) > 500*1024 { // 500KB лимит для безопасности
		log.Printf("%s: [Very large content, %d bytes] - skipping log for safety", prefix, len(body))
		return
	}

	decompressedBody := decompressIfNeeded(body, headers)
	
	if utf8.Valid(decompressedBody) {
		log.Printf("%s: %s", prefix, string(decompressedBody))
	} else {
		log.Printf("%s: [Non-UTF8 data, %d bytes]", prefix, len(decompressedBody))
		logHexDump(prefix, body)
	}
}

// logBodyTruncated показывает body с обрезанием
func logBodyTruncated(prefix string, body []byte, contentType string, headers http.Header) {
	decompressedBody := decompressIfNeeded(body, headers)
	
	if utf8.Valid(decompressedBody) {
		text := string(decompressedBody)
		log.Printf("%s: %s", prefix, truncateString(text, logSettings.MaxLogLength))
	} else {
		log.Printf("%s: [Non-UTF8 data, %d bytes]", prefix, len(decompressedBody))
		logHexDump(prefix, body)
	}
}

// logBodyJSONSmart показывает JSON полностью, остальное обрезает
func logBodyJSONSmart(prefix string, body []byte, contentType string, headers http.Header) {
	decompressedBody := decompressIfNeeded(body, headers)
	
	// Проверяем, является ли контент JSON
	if isJSONContent(contentType, decompressedBody) {
		// Для JSON форматируем и выводим полностью
		if formatted := formatJSON(decompressedBody); formatted != "" {
			log.Printf("%s (JSON formatted):\n%s", prefix, formatted)
		} else {
			// Если не удалось отформатировать, выводим как есть
			log.Printf("%s (JSON): %s", prefix, string(decompressedBody))
		}
		return
	}

	// Для не-JSON применяем truncation
	if utf8.Valid(decompressedBody) {
		text := string(decompressedBody)
		log.Printf("%s: %s", prefix, truncateString(text, logSettings.MaxLogLength))
	} else {
		log.Printf("%s: [Non-UTF8 data, %d bytes]", prefix, len(decompressedBody))
		logHexDump(prefix, body)
	}
}

// logHexDump показывает hex дамп для бинарных данных
func logHexDump(prefix string, body []byte) {
	sampleSize := min(64, len(body))
	hexSample := hex.EncodeToString(body[:sampleSize])
	log.Printf("%s (hex sample): %s", prefix, hexSample)
	if len(body) > sampleSize {
		log.Printf("%s (hex): ... +%d more bytes", prefix, len(body)-sampleSize)
	}
}

// decompressIfNeeded распаковывает данные если они сжаты
func decompressIfNeeded(body []byte, headers http.Header) []byte {
	if headers == nil {
		return body
	}

	contentEncoding := headers.Get("Content-Encoding")
	if contentEncoding == "" {
		return body
	}

	switch strings.ToLower(contentEncoding) {
	case "gzip":
		if decompressed, err := decompressGzip(body); err == nil {
			log.Printf("🔓 Decompressed gzip: %d -> %d bytes", len(body), len(decompressed))
			return decompressed
		}
	}
	
	return body
}

// isJSONContent проверяет, является ли контент JSON
func isJSONContent(contentType string, body []byte) bool {
	// Проверяем Content-Type
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		return true
	}

	// Проверяем структуру данных
	if len(body) == 0 {
		return false
	}

	// Пробуем распарсить как JSON
	var js interface{}
	return json.Unmarshal(body, &js) == nil
}

// formatJSON форматирует JSON для красивого вывода
func formatJSON(body []byte) string {
	var js interface{}
	if err := json.Unmarshal(body, &js); err != nil {
		return ""
	}

	formatted, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return ""
	}

	return string(formatted)
}

// Остальные вспомогательные функции
func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	
	return io.ReadAll(reader)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... [truncated]"
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		if shouldSkipHeader(name) {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func shouldSkipHeader(name string) bool {
	skipHeaders := []string{
		"Connection",
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}

	lowerName := strings.ToLower(name)
	for _, skipHeader := range skipHeaders {
		if lowerName == strings.ToLower(skipHeader) {
			return true
		}
	}
	return false
}
