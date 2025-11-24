package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ResponseOverride конфигурация для подмены ответа
type ResponseOverride struct {
	Name          string            `json:"name"`          // Имя правила для логов
	Method        string            `json:"method"`        // HTTP метод (* для любого)
	URLPattern    string            `json:"url_pattern"`   // Паттерн URL (поддерживает regex)
	IsRegex       bool              `json:"is_regex"`      // Использовать regex для паттерна
	StatusCode    int               `json:"status_code"`   // HTTP статус код
	Headers       map[string]string `json:"headers"`       // Заголовки ответа
	BodyFile      string            `json:"body_file"`     // Путь к файлу с телом ответа
	BodyText      string            `json:"body_text"`     // Текст ответа (альтернатива файлу)
	Enabled       bool              `json:"enabled"`       // Включено ли правило
	TriggerAfter  int               `json:"trigger_after"` // После скольких запросов срабатывать (0 = сразу)
	MaxTriggers   int               `json:"max_triggers"`  // Максимальное количество срабатываний (-1 = бесконечно)
	ResetAfter    int               `json:"reset_after"`   // Сброс счетчика через N запросов (0 = не сбрасывать)
	compiledRegex *regexp.Regexp    // Скомпилированный regex (не сериализуется)
	requestCount  int               // Счетчик запросов (не сериализуется)
	triggerCount  int               // Счетчик срабатываний (не сериализуется)
	mutex         sync.Mutex        // Мьютекс для безопасности (не сериализуется)
}

// Config конфигурация всех подмен
type Config struct {
	Overrides []ResponseOverride `json:"overrides"`
}

// LogSettings настройки логирования
type LogSettings struct {
	ShowRequestBody     bool
	ShowResponseBody    bool
	ShowRequestHeaders  bool
	ShowResponseHeaders bool
	BodyLogMode         string // "full", "truncate", "none", "json_full"
	MaxLogLength        int
	EnableStreaming     bool // Включить стриминговый режим (без буферизации)
}

// ProxySettings настройки прокси
type ProxySettings struct {
	Enabled       bool
	URL           string
	Username      string
	Password      string
	SkipTLSVerify bool
	Timeout       time.Duration
}

// CacheEntry запись в кеше
type CacheEntry struct {
	StatusCode  int
	Headers     http.Header
	Body        []byte
	CachedAt    time.Time
	ExpiresAt   time.Time
	RequestURL  string
	RequestHash string
}

// CacheSettings настройки кеширования
type CacheSettings struct {
	Enabled    bool
	TTL        time.Duration
	KeyHeaders []string // Дополнительные заголовки для ключа кеша
}

var config Config
var logSettings LogSettings
var proxySettings ProxySettings
var cacheSettings CacheSettings
var httpClient *http.Client
var responseCache sync.Map // map[string]*CacheEntry
var cacheHits int64
var cacheMisses int64

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

	// Настраиваем кеширование
	setupCacheSettings()

	// Настраиваем прокси
	setupProxySettings()

	// Создаем HTTP клиент с настройками прокси
	setupHTTPClient()

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
	printCacheSettings()
	printProxySettings()

	if targetURL.Path != "" && targetURL.Path != "/" {
		log.Printf("Базовый path: %s", targetURL.Path)
	}

	// Запускаем сервер
	err = http.ListenAndServe("0.0.0.0:"+port, nil)
	if err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}

func setupLogSettings() {
	// Настройки логирования body
	logSettings.ShowRequestBody = os.Getenv("LOG_REQUEST_BODY") != "false"
	logSettings.ShowResponseBody = os.Getenv("LOG_RESPONSE_BODY") != "false"

	// Настройки логирования headers
	logSettings.ShowRequestHeaders = os.Getenv("LOG_REQUEST_HEADERS") != "false"
	logSettings.ShowResponseHeaders = os.Getenv("LOG_RESPONSE_HEADERS") != "false"

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

	// Настройка стримингового режима
	logSettings.EnableStreaming = os.Getenv("ENABLE_STREAMING") == "true"
}

func setupCacheSettings() {
	cacheTTLStr := os.Getenv("CACHE_TTL")
	if cacheTTLStr == "" {
		cacheSettings.Enabled = false
		return
	}

	ttl, err := time.ParseDuration(cacheTTLStr)
	if err != nil {
		log.Printf("⚠️  Неверный формат CACHE_TTL: %s, кеширование отключено", cacheTTLStr)
		cacheSettings.Enabled = false
		return
	}

	cacheSettings.Enabled = true
	cacheSettings.TTL = ttl

	// Читаем дополнительные заголовки для ключа кеша
	keyHeaders := os.Getenv("CACHE_KEY_HEADERS")
	if keyHeaders != "" {
		cacheSettings.KeyHeaders = strings.Split(keyHeaders, ",")
		for i := range cacheSettings.KeyHeaders {
			cacheSettings.KeyHeaders[i] = strings.TrimSpace(cacheSettings.KeyHeaders[i])
		}
	}
}

func printCacheSettings() {
	log.Printf("💾 Настройки кеширования:")
	if cacheSettings.Enabled {
		log.Printf("   Enabled: ✅")
		log.Printf("   TTL: %v", cacheSettings.TTL)
		if len(cacheSettings.KeyHeaders) > 0 {
			log.Printf("   Key Headers: %v", cacheSettings.KeyHeaders)
		}
	} else {
		log.Printf("   Enabled: ❌")
	}
	log.Printf("")
	log.Printf("🔧 Переменные окружения для кеширования:")
	log.Printf("   - CACHE_TTL=3h - кешировать запросы на 3 часа")
	log.Printf("   - CACHE_TTL=30m - кешировать запросы на 30 минут")
	log.Printf("   - CACHE_KEY_HEADERS=X-Ya-Dest-Url,X-Custom - учитывать заголовки в ключе кеша")
	log.Printf("")
}

func setupProxySettings() {
	proxyURL := os.Getenv("UPSTREAM_PROXY")
	if proxyURL == "" {
		proxySettings.Enabled = false
		return
	}

	proxySettings.Enabled = true
	proxySettings.URL = proxyURL
	proxySettings.Username = os.Getenv("UPSTREAM_PROXY_USERNAME")
	proxySettings.Password = os.Getenv("UPSTREAM_PROXY_PASSWORD")
	proxySettings.SkipTLSVerify = os.Getenv("UPSTREAM_PROXY_SKIP_TLS") == "true"

	// Настройка таймаута
	timeoutStr := os.Getenv("UPSTREAM_PROXY_TIMEOUT")
	if timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			proxySettings.Timeout = timeout
		} else {
			log.Printf("⚠️  Неверный формат UPSTREAM_PROXY_TIMEOUT: %s, используется 30s", timeoutStr)
			proxySettings.Timeout = 30 * time.Second
		}
	} else {
		proxySettings.Timeout = 30 * time.Second
	}
}

func setupHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: proxySettings.SkipTLSVerify,
		},
	}

	if proxySettings.Enabled {
		proxyURL, err := url.Parse(proxySettings.URL)
		if err != nil {
			log.Fatalf("❌ Ошибка парсинга URL прокси: %v", err)
		}

		// Добавляем аутентификацию если указана
		if proxySettings.Username != "" {
			proxyURL.User = url.UserPassword(proxySettings.Username, proxySettings.Password)
		}

		transport.Proxy = http.ProxyURL(proxyURL)
		log.Printf("🔗 Настроен upstream прокси: %s", proxySettings.URL)
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   proxySettings.Timeout,
	}
}

func printLogSettings() {
	log.Printf("📋 Настройки логирования:")
	log.Printf("   Request Body: %v", logSettings.ShowRequestBody)
	log.Printf("   Response Body: %v", logSettings.ShowResponseBody)
	log.Printf("   Request Headers: %v", logSettings.ShowRequestHeaders)
	log.Printf("   Response Headers: %v", logSettings.ShowResponseHeaders)
	log.Printf("   Body Log Mode: %s", logSettings.BodyLogMode)
	if logSettings.BodyLogMode == "truncate" {
		log.Printf("   Max Log Length: %d", logSettings.MaxLogLength)
	}
	log.Printf("   Streaming Mode: %v", logSettings.EnableStreaming)
	log.Printf("")
	log.Printf("💡 Доступные режимы BODY_LOG_MODE:")
	log.Printf("   - 'full' - показать все body полностью")
	log.Printf("   - 'truncate' - обрезать длинные body")
	log.Printf("   - 'json_full' - JSON полностью, остальное обрезать (по умолчанию)")
	log.Printf("   - 'none' - не показывать body")
	log.Printf("")
	log.Printf("🎛️  Настройки заголовков:")
	log.Printf("   - LOG_REQUEST_HEADERS=false - отключить заголовки запроса")
	log.Printf("   - LOG_RESPONSE_HEADERS=false - отключить заголовки ответа")
	log.Printf("")
	log.Printf("🚀 Стриминговый режим:")
	log.Printf("   - ENABLE_STREAMING=true - включить стриминг (отключает логирование body)")
	log.Printf("")
}

func printProxySettings() {
	log.Printf("🌐 Настройки upstream прокси:")
	if proxySettings.Enabled {
		log.Printf("   Enabled: ✅")
		log.Printf("   URL: %s", proxySettings.URL)
		if proxySettings.Username != "" {
			log.Printf("   Auth: %s:***", proxySettings.Username)
		} else {
			log.Printf("   Auth: не используется")
		}
		log.Printf("   Skip TLS Verify: %v", proxySettings.SkipTLSVerify)
		log.Printf("   Timeout: %v", proxySettings.Timeout)
	} else {
		log.Printf("   Enabled: ❌")
	}
	log.Printf("")
	log.Printf("🔧 Переменные окружения для прокси:")
	log.Printf("   - UPSTREAM_PROXY=http://proxy.example.com:8080")
	log.Printf("   - UPSTREAM_PROXY_USERNAME=username")
	log.Printf("   - UPSTREAM_PROXY_PASSWORD=password")
	log.Printf("   - UPSTREAM_PROXY_SKIP_TLS=true")
	log.Printf("   - UPSTREAM_PROXY_TIMEOUT=30s")
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
				Name:         "Yandex bindings - срабатывает после 3 запросов",
				Method:       "*",
				URLPattern:   "/bindings",
				IsRegex:      false,
				StatusCode:   200,
				TriggerAfter: 3,
				MaxTriggers:  2,
				ResetAfter:   10,
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-Custom":     "overridden-after-3-requests",
				},
				BodyFile: "responses/bindings.json",
				Enabled:  true,
			},
			{
				Name:         "API users - мгновенная подмена",
				Method:       "GET",
				URLPattern:   `/api/users/\d+`,
				IsRegex:      true,
				StatusCode:   200,
				TriggerAfter: 0,  // срабатывает сразу
				MaxTriggers:  -1, // бесконечно
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				BodyText: `{"id": 123, "name": "Mock User", "email": "mock@example.com", "mocked": true}`,
				Enabled:  false,
			},
			{
				Name:         "Error simulation - после 5 запросов",
				Method:       "POST",
				URLPattern:   "/api/submit",
				IsRegex:      false,
				StatusCode:   500,
				TriggerAfter: 5,
				MaxTriggers:  1, // только один раз
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
			"message":      "This is a mocked response from file (triggered after N requests)",
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
		"overrides":    stats,
		"total_rules":  len(config.Overrides),
		"active_rules": countActiveOverrides(),
		"log_settings": map[string]interface{}{
			"show_request_body":     logSettings.ShowRequestBody,
			"show_response_body":    logSettings.ShowResponseBody,
			"show_request_headers":  logSettings.ShowRequestHeaders,
			"show_response_headers": logSettings.ShowResponseHeaders,
			"body_log_mode":         logSettings.BodyLogMode,
			"max_log_length":        logSettings.MaxLogLength,
		},
		"proxy_settings": map[string]interface{}{
			"enabled":         proxySettings.Enabled,
			"url":             proxySettings.URL,
			"has_auth":        proxySettings.Username != "",
			"skip_tls_verify": proxySettings.SkipTLSVerify,
			"timeout":         proxySettings.Timeout.String(),
		},
		"cache_settings": map[string]interface{}{
			"enabled":      cacheSettings.Enabled,
			"ttl":          cacheSettings.TTL.String(),
			"cache_hits":   atomic.LoadInt64(&cacheHits),
			"cache_misses": atomic.LoadInt64(&cacheMisses),
			"cache_size":   getCacheSize(),
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

	proxyInfo := proxyURL.String()
	if proxySettings.Enabled {
		proxyInfo += " (via " + proxySettings.URL + ")"
	}
	log.Printf("🔄 %s %s -> %s", r.Method, r.URL.String(), proxyInfo)

	// Логируем заголовки входящего запроса
	if logSettings.ShowRequestHeaders {
		logHeaders("📤 Request Headers", r.Header)
	}

	// Проверяем, есть ли подмена для этого запроса
	// Передаем полный URL с query параметрами
	fullURL := r.URL.Path
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}
	if override := findMatchingOverride(r.Method, fullURL); override != nil {
		log.Printf("🎭 Применяем подмену: %s", override.Name)
		handleOverride(w, r, override)
		return
	}

	// Выбираем режим проксирования
	// Приоритет: кеширование > стриминг (кеш требует буферизации)
	if cacheSettings.Enabled && logSettings.EnableStreaming {
		log.Printf("⚠️  Кеширование имеет приоритет над стримингом (используется буферизованный режим)")
	}

	if logSettings.EnableStreaming && !cacheSettings.Enabled {
		log.Printf("🚀 Стриминговый режим включен")
		streamingProxyRequest(w, r, proxyURL, targetURL)
	} else {
		bufferedProxyRequest(w, r, proxyURL, targetURL)
	}
}

// bufferedProxyRequest - исходный режим с буферизацией для логирования
func bufferedProxyRequest(w http.ResponseWriter, r *http.Request, proxyURL *url.URL, targetURL *url.URL) {
	// Проверяем кеш если включен
	if cacheSettings.Enabled {
		cacheKey := generateCacheKey(r.Method, proxyURL.String(), r.Header)
		if cached := getCachedResponse(cacheKey); cached != nil {
			atomic.AddInt64(&cacheHits, 1)
			log.Printf("💾 Ответ из кеша (срок действия до %s)", cached.ExpiresAt.Format("15:04:05"))
			serveCachedResponse(w, cached)
			return
		}
		atomic.AddInt64(&cacheMisses, 1)
	}

	// Читаем тело запроса ПОЛНОСТЬЮ
	var requestBody []byte
	var bodyReader io.Reader

	if r.Body != nil {
		var err error
		requestBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Ошибка чтения тела запроса", http.StatusBadRequest)
			log.Printf("❌ Ошибка чтения тела запроса: %v", err)
			return
		}
		r.Body.Close()

		// Логируем тело входящего запроса
		if len(requestBody) > 0 && logSettings.ShowRequestBody {
			logBody("📤 Request Body", requestBody, r.Header.Get("Content-Type"), r.Header)
		}

		// Создаем новый Reader для прокси запроса
		bodyReader = bytes.NewReader(requestBody)
	}

	// Создаем новый HTTP запрос
	proxyReq, err := http.NewRequest(r.Method, proxyURL.String(), bodyReader)
	if err != nil {
		http.Error(w, "Ошибка создания запроса", http.StatusInternalServerError)
		log.Printf("❌ Ошибка создания запроса: %v", err)
		return
	}

	// Копируем заголовки из оригинального запроса
	copyHeaders(proxyReq.Header, r.Header)

	// Устанавливаем правильный Host заголовок
	proxyReq.Host = targetURL.Host

	// ВАЖНО: Убираем Transfer-Encoding и устанавливаем Content-Length
	if len(requestBody) > 0 {
		// Принудительно устанавливаем Content-Length
		proxyReq.ContentLength = int64(len(requestBody))
		proxyReq.Header.Set("Content-Length", strconv.Itoa(len(requestBody)))

		// Убираем заголовки, связанные с chunked encoding
		proxyReq.Header.Del("Transfer-Encoding")

		log.Printf("📏 Content-Length установлен: %d bytes", len(requestBody))
	} else {
		// Для запросов без тела также убираем Transfer-Encoding
		proxyReq.Header.Del("Transfer-Encoding")
		proxyReq.ContentLength = 0
	}

	// Выполняем запрос через настроенный клиент (с прокси если настроен)
	resp, err := httpClient.Do(proxyReq)
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

	// Логируем статус ответа
	log.Printf("📥 Response Status: %d %s", resp.StatusCode, resp.Status)

	// Логируем заголовки ответа
	if logSettings.ShowResponseHeaders {
		logHeaders("📥 Response Headers", resp.Header)
	}

	// Логируем тело ответа
	if len(responseBody) > 0 && logSettings.ShowResponseBody {
		logBody("📥 Response Body", responseBody, resp.Header.Get("Content-Type"), resp.Header)
	}

	// Сохраняем в кеш если включен
	if cacheSettings.Enabled {
		cacheKey := generateCacheKey(r.Method, proxyURL.String(), r.Header)
		cacheResponse(cacheKey, resp.StatusCode, resp.Header, responseBody, proxyURL.String())
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

// streamingProxyRequest - новый стриминговый режим без буферизации
func streamingProxyRequest(w http.ResponseWriter, r *http.Request, proxyURL *url.URL, targetURL *url.URL) {
	// Создаем новый HTTP запрос напрямую с Body из исходного запроса
	proxyReq, err := http.NewRequest(r.Method, proxyURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Ошибка создания запроса", http.StatusInternalServerError)
		log.Printf("❌ Ошибка создания запроса: %v", err)
		return
	}

	// Копируем заголовки из оригинального запроса
	copyHeaders(proxyReq.Header, r.Header)

	// Устанавливаем правильный Host заголовок
	proxyReq.Host = targetURL.Host

	// В стриминговом режиме сохраняем исходный ContentLength
	// Для SSE и chunked encoding это может быть -1
	proxyReq.ContentLength = r.ContentLength

	if r.ContentLength >= 0 {
		log.Printf("🚀 Стриминг: Content-Length=%d", r.ContentLength)
	} else {
		log.Printf("🚀 Стриминг: chunked encoding или unknown length")
	}

	// Выполняем запрос через настроенный клиент
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		http.Error(w, "Ошибка выполнения запроса", http.StatusBadGateway)
		log.Printf("❌ Ошибка выполнения запроса: %v", err)
		return
	}
	defer resp.Body.Close()

	// Логируем статус ответа
	log.Printf("📥 Response Status: %d %s", resp.StatusCode, resp.Status)

	// Логируем заголовки ответа
	if logSettings.ShowResponseHeaders {
		logHeaders("📥 Response Headers", resp.Header)
	}

	// Копируем заголовки ответа ПЕРЕД WriteHeader
	copyHeaders(w.Header(), resp.Header)

	// Проверяем, является ли это SSE потоком
	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream")

	if isSSE {
		log.Printf("🌊 Обнаружен SSE поток (text/event-stream)")
		// Для SSE принудительно устанавливаем важные заголовки
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// Убираем Content-Length для SSE потоков
		w.Header().Del("Content-Length")
	}

	// Устанавливаем статус код
	w.WriteHeader(resp.StatusCode)

	// Получаем Flusher для немедленной отправки данных (важно для SSE)
	flusher, canFlush := w.(http.Flusher)
	if !canFlush {
		log.Printf("⚠️  ResponseWriter не поддерживает Flush")
	}

	// СТРИМИНГ: копируем с поддержкой Flush для SSE
	if isSSE && canFlush {
		// Для SSE используем буферизованное копирование с Flush
		bytesWritten := streamWithFlush(w, resp.Body, flusher)
		log.Printf("🌊 SSE стриминг завершен: %d bytes передано", bytesWritten)
	} else {
		// Обычный стриминг
		bytesWritten, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("❌ Ошибка стриминга ответа: %v", err)
			return
		}
		log.Printf("🚀 Стриминг завершен: %d bytes передано", bytesWritten)
	}

	log.Printf("✅ Запрос завершен\n")
}

// streamWithFlush - стриминг с принудительной отправкой для SSE
func streamWithFlush(w io.Writer, src io.Reader, flusher http.Flusher) int64 {
	buf := make([]byte, 4096) // Небольшой буфер для частой отправки
	var written int64

	for {
		n, err := src.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			written += int64(n)
			// Немедленно отправляем данные клиенту (критично для SSE)
			flusher.Flush()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("⚠️  Ошибка чтения SSE потока: %v", err)
			}
			break
		}
	}

	return written
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

	// Логируем заголовки подмены
	if logSettings.ShowResponseHeaders && len(override.Headers) > 0 {
		log.Printf("   Override Headers:")
		headers := make([]string, 0, len(override.Headers))
		for key, _ := range override.Headers {
			headers = append(headers, key)
		}
		sort.Strings(headers)
		for _, key := range headers {
			log.Printf("     %s: %s", key, override.Headers[key])
		}
	}

	if len(responseBody) > 0 && logSettings.ShowResponseBody {
		contentType := override.Headers["Content-Type"]
		logBody("   Body", responseBody, contentType, nil)
	}

	log.Printf("✅ Подмена завершена\n")
}

// logHeaders логирует HTTP заголовки
func logHeaders(prefix string, headers http.Header) {
	if len(headers) == 0 {
		log.Printf("%s: [None]", prefix)
		return
	}

	// Сортируем заголовки для консистентного вывода
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	log.Printf("%s:", prefix)
	for _, key := range keys {
		values := headers[key]
		if len(values) == 1 {
			log.Printf("  %s: %s", key, values[0])
		} else {
			log.Printf("  %s: %v", key, values)
		}
	}
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
		"Upgrade",
	}

	// В стриминговом режиме НЕ пропускаем Transfer-Encoding
	if !logSettings.EnableStreaming {
		skipHeaders = append(skipHeaders, "Transfer-Encoding")
	}

	lowerName := strings.ToLower(name)
	for _, skipHeader := range skipHeaders {
		if lowerName == strings.ToLower(skipHeader) {
			return true
		}
	}
	return false
}

// generateCacheKey генерирует ключ кеша на основе метода, URL и заголовков
func generateCacheKey(method, url string, headers http.Header) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte(url))

	// Добавляем важные заголовки в ключ кеша
	if auth := headers.Get("Authorization"); auth != "" {
		h.Write([]byte("Authorization:"))
		h.Write([]byte(auth))
	}
	if contentType := headers.Get("Content-Type"); contentType != "" {
		h.Write([]byte("Content-Type:"))
		h.Write([]byte(contentType))
	}

	// Добавляем дополнительные заголовки из настроек
	for _, headerName := range cacheSettings.KeyHeaders {
		if headerValue := headers.Get(headerName); headerValue != "" {
			h.Write([]byte(headerName + ":"))
			h.Write([]byte(headerValue))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// getCachedResponse получает ответ из кеша
func getCachedResponse(key string) *CacheEntry {
	if val, ok := responseCache.Load(key); ok {
		entry := val.(*CacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			return entry
		}
		// Удаляем устаревшую запись
		responseCache.Delete(key)
	}
	return nil
}

// cacheResponse сохраняет ответ в кеш
func cacheResponse(key string, statusCode int, headers http.Header, body []byte, url string) {
	now := time.Now()
	entry := &CacheEntry{
		StatusCode:  statusCode,
		Headers:     cloneHeaders(headers),
		Body:        body,
		CachedAt:    now,
		ExpiresAt:   now.Add(cacheSettings.TTL),
		RequestURL:  url,
		RequestHash: key,
	}
	responseCache.Store(key, entry)
	log.Printf("💾 Ответ сохранен в кеш (срок действия до %s)", entry.ExpiresAt.Format("15:04:05"))
}

// serveCachedResponse отправляет кешированный ответ клиенту
func serveCachedResponse(w http.ResponseWriter, entry *CacheEntry) {
	log.Printf("📥 Response Status: %d (cached)", entry.StatusCode)

	// Логируем заголовки с отметкой кеша
	if logSettings.ShowResponseHeaders {
		logHeaders("📥 Response Headers (cached)", entry.Headers)
	}

	// Логируем тело с обрезанием
	if len(entry.Body) > 0 && logSettings.ShowResponseBody {
		// Принудительно обрезаем кешированные логи
		contentType := entry.Headers.Get("Content-Type")
		logCachedBody("📥 Response Body (cached)", entry.Body, contentType, entry.Headers)
	}

	// Копируем заголовки
	copyHeaders(w.Header(), entry.Headers)

	// Добавляем заголовок о кешировании
	w.Header().Set("X-Cache", "HIT")
	w.Header().Set("X-Cache-Expires", entry.ExpiresAt.Format(time.RFC3339))

	// Устанавливаем статус код
	w.WriteHeader(entry.StatusCode)

	// Отправляем тело
	w.Write(entry.Body)

	log.Printf("✅ Запрос завершен (из кеша)\n")
}

// logCachedBody логирует кешированное тело с обрезанием
func logCachedBody(prefix string, body []byte, contentType string, headers http.Header) {
	if len(body) == 0 {
		log.Printf("%s: [Empty]", prefix)
		return
	}

	decompressedBody := decompressIfNeeded(body, headers)

	// Всегда обрезаем для кешированных ответов
	maxLen := logSettings.MaxLogLength
	if maxLen == 0 {
		maxLen = 2000
	}

	if utf8.Valid(decompressedBody) {
		text := string(decompressedBody)
		if len(text) > maxLen {
			log.Printf("%s: %s... [truncated, total: %d bytes]", prefix, text[:maxLen], len(text))
		} else {
			log.Printf("%s: %s", prefix, text)
		}
	} else {
		log.Printf("%s: [Non-UTF8 data, %d bytes]", prefix, len(decompressedBody))
		logHexDump(prefix, body)
	}
}

// cloneHeaders создает копию заголовков
func cloneHeaders(headers http.Header) http.Header {
	clone := make(http.Header)
	for key, values := range headers {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}

// getCacheSize возвращает количество записей в кеше
func getCacheSize() int {
	size := 0
	responseCache.Range(func(key, value interface{}) bool {
		size++
		return true
	})
	return size
}
