// File: esp32_health_fhir_final.ino
// Dual-core ESP32 firmware: sensors, robust PTT extraction, SPIFFS model load,
// confidence gating, FHIR bundle (ArduinoJson), AES-GCM encryption, MQTT publish.

// Required libraries:
//   ArduinoJson, PubSubClient, MAX30105, SparkFun_ICM_20948, Adafruit_MLX90614,
//   mbedtls (comes with ESP32 core), SPIFFS (built-in)

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <SPI.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include <LiquidCrystal_I2C.h>
#include <MAX30105.h>
#include <SparkFun_ICM_20948.h>
#include <Adafruit_MLX90614.h>
#include <mbedtls/gcm.h>

// ===== CONFIG =====
#define I2C_SDA 21
#define I2C_SCL 22

#define ECG_PIN 34
#define ECG_LO_PLUS 25
#define ECG_LO_MINUS 26

#define ADS_CS 5
#define ADS_SCK 18
#define ADS_MISO 19
#define ADS_MOSI 23
#define ADS_DRDY 27
#define ADS_START 32
#define ADS_PWDN 33

#define BUZZER_PIN 13
#define BTN1 14
#define BTN2 15

const char* ssid = "YOUR_WIFI";
const char* password = "YOUR_PASS";
const char* mqtt_server = "broker.hivemq.com";
const int mqtt_port = 1883;
const char* mqtt_topic = "health/fhir";

// AES key prototype only. Replace with secure provisioning in production.
const uint8_t AES_KEY[16] = {
  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

// ===== OBJECTS =====
LiquidCrystal_I2C lcd(0x27, 16, 2);
MAX30105 particleSensor;
ICM_20948_I2C imu;
Adafruit_MLX90614 mlx = Adafruit_MLX90614();
WiFiClient espClient;
PubSubClient client(espClient);

// ===== SHARED GLOBALS =====
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

volatile float heartRate = 75.0;
volatile float SpO2 = 98.0;
volatile float tempC = 36.5;
volatile float SBP = 120.0;
volatile float DBP = 80.0;
volatile float RespRate = 16.0;
volatile float PTT_ms = 120.0;

volatile long ads_ecg_ch1 = 0;
volatile long ads_ecg_ch2 = 0;
volatile long ads_resp_raw = 0;

volatile unsigned long lastRPeakMicros = 0;
volatile unsigned long lastPPGMicros = 0;

// PTT extraction buffers
#define SAMPLE_HZ 500
#define ECG_BUF_LEN (SAMPLE_HZ * 5)
volatile int ecg_buf[ECG_BUF_LEN];
volatile unsigned long ecg_ts[ECG_BUF_LEN];
volatile int ecg_idx = 0;

std::vector<unsigned long> rpeaks_us;
std::vector<unsigned long> ppg_foot_us;
std::vector<float> ptt_list;

// IR amplitude window
volatile uint64_t ir_sum_window = 0;
volatile int ir_count_window = 0;

// IMU magnitude
volatile float acc_mag = 0.0;

// Model loaded from SPIFFS
struct LinearModel {
  float intercept;
  std::vector<float> coefs;
  bool valid = false;
};
LinearModel sbp_model, dbp_model;
std::vector<String> model_features;

// ===== UTILITIES =====
void bytesToHex(const uint8_t *in, size_t len, char *out) {
  const char hex[] = "0123456789ABCDEF";
  for (size_t i = 0; i < len; ++i) {
    out[i*2]     = hex[(in[i] >> 4) & 0x0F];
    out[i*2 + 1] = hex[in[i] & 0x0F];
  }
  out[len*2] = '\0';
}

String encryptGCM(const String &plaintext) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_KEY, 128);
  if (ret != 0) { mbedtls_gcm_free(&gcm); return String(""); }
  uint8_t iv[12]; esp_fill_random(iv, sizeof(iv));
  size_t len = plaintext.length();
  uint8_t *ciphertext = (uint8_t*)malloc(len);
  if (!ciphertext) { mbedtls_gcm_free(&gcm); return String(""); }
  uint8_t tag[16];
  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len,
                                  iv, sizeof(iv), NULL, 0,
                                  (const unsigned char*)plaintext.c_str(),
                                  ciphertext, sizeof(tag), tag);
  if (ret != 0) { free(ciphertext); mbedtls_gcm_free(&gcm); return String(""); }
  mbedtls_gcm_free(&gcm);

  size_t outLen = sizeof(iv) + len + sizeof(tag);
char *hexOut = (char*)malloc(outLen * 2 + 1);
  if (!hexOut) { free(ciphertext); return String(""); }
  bytesToHex(iv, sizeof(iv), hexOut);
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = ciphertext[i];
    hexOut[(sizeof(iv) + i) * 2]     = "0123456789ABCDEF"[(b >> 4) & 0x0F];
    hexOut[(sizeof(iv) + i) * 2 + 1] = "0123456789ABCDEF"[b & 0x0F];
  }
  for (size_t i = 0; i < sizeof(tag); ++i) {
    uint8_t b = tag[i];
    hexOut[(sizeof(iv) + len + i) * 2]     = "0123456789ABCDEF"[(b >> 4) & 0x0F];
    hexOut[(sizeof(iv) + len + i) * 2 + 1] = "0123456789ABCDEF"[b & 0x0F];
  }
  hexOut[outLen * 2] = '\0';
  String outStr = String(hexOut);
  free(hexOut);
  free(ciphertext);
  return outStr;
}

// ===== ADS1292R init/read (improved) =====
void ads1292_init() {
  pinMode(ADS_CS, OUTPUT);
  pinMode(ADS_DRDY, INPUT);
  pinMode(ADS_START, OUTPUT);
  pinMode(ADS_PWDN, OUTPUT);
  digitalWrite(ADS_CS, HIGH);
  digitalWrite(ADS_START, HIGH);
  digitalWrite(ADS_PWDN, HIGH);
  SPI.begin(ADS_SCK, ADS_MISO, ADS_MOSI, ADS_CS);
  delay(10);

  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE1));
  digitalWrite(ADS_CS, LOW);
  SPI.transfer(0x06); // RESET
  digitalWrite(ADS_CS, HIGH);
  SPI.endTransaction();
  delay(50);

  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE1));
  digitalWrite(ADS_CS, LOW);
  SPI.transfer(0x11); // SDATAC
  digitalWrite(ADS_CS, HIGH);
  SPI.endTransaction();
  delay(10);

  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE1));
  digitalWrite(ADS_CS, LOW);
  SPI.transfer(0x40 | 0x01); // WREG start 0x01
  SPI.transfer(0x04);       // write 5 regs
  SPI.transfer(0x96);       // CONFIG1 example
  SPI.transfer(0x10);       // CONFIG2
  SPI.transfer(0x60);       // LOFF
  SPI.transfer(0x10);       // CH1SET
  SPI.transfer(0x10);       // CH2SET
  digitalWrite(ADS_CS, HIGH);
  SPI.endTransaction();
  delay(10);

  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE1));
  digitalWrite(ADS_CS, LOW);
  SPI.transfer(0x08); // START
  digitalWrite(ADS_CS, HIGH);
  SPI.endTransaction();
  delay(10);

  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE1));
  digitalWrite(ADS_CS, LOW);
  SPI.transfer(0x10); // RDATAC
  digitalWrite(ADS_CS, HIGH);
  SPI.endTransaction();
  delay(10);
}

long ads1292_read24_signed() {
  uint8_t b1 = SPI.transfer(0x00);
  uint8_t b2 = SPI.transfer(0x00);
  uint8_t b3 = SPI.transfer(0x00);
  long v = ((long)b1 << 16) | ((long)b2 << 8) | (long)b3;
  if (v & 0x800000) v |= 0xFF000000;
  return v;
}

void ads1292_read_once() {
  if (digitalRead(ADS_DRDY) == LOW) {
    SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE1));
    digitalWrite(ADS_CS, LOW);
    long ch1 = ads1292_read24_signed();
    long ch2 = ads1292_read24_signed();
    digitalWrite(ADS_CS, HIGH);
    SPI.endTransaction();
    portENTER_CRITICAL(&mux);
    ads_ecg_ch1 = ch1;
    ads_ecg_ch2 = ch2;
    ads_resp_raw = ch2;
    portEXIT_CRITICAL(&mux);
  }
}

// ===== PTT extraction (simple, robust) =====
float ecg_hp_prev = 0, ecg_lp_prev = 0;
float ecg_highpass(float x) {
  float y = 0.995f * (ecg_hp_prev + x - ecg_lp_prev);
  ecg_lp_prev = x;
  ecg_hp_prev = y;
  return y;
}
float ecg_lowpass(float x) {
  float alpha = 0.1f;
  float y = alpha * x + (1 - alpha) * ecg_lp_prev;
  ecg_lp_prev = y;
  return y;
}

void process_ecg_sample(int raw, unsigned long ts_us) {
  float hp = ecg_highpass((float)raw);
  float lp = ecg_lowpass(hp);
  ecg_buf[ecg_idx] = (int)lp;
  ecg_ts[ecg_idx] = ts_us;
  ecg_idx = (ecg_idx + 1) % ECG_BUF_LEN;

  static float threshold = 0;
  static float peak_val = 0;
  static unsigned long peak_time = 0;
  if (lp > threshold) {
    if (lp > peak_val) { peak_val = lp; peak_time = ts_us; }
  } else {
    if (peak_val > 200) {
      if (rpeaks_us.empty() || (peak_time - rpeaks_us.back()) > 300000) {
        rpeaks_us.push_back(peak_time);
        if (rpeaks_us.size() > 500) rpeaks_us.erase(rpeaks_us.begin());
      }
    }
    threshold = 0.995f * threshold + 0.005f * peak_val;
    peak_val = 0;
  }
}
void process_ppg_sample(long ir_value, unsigned long ts_us) {
  static long prev_ir = 0;
  static long prev_diff = 0;
  long diff = ir_value - prev_ir;
  if (prev_diff < 0 && diff > 0 && ir_value < 50000) {
    ppg_foot_us.push_back(ts_us);
    if (ppg_foot_us.size() > 500) ppg_foot_us.erase(ppg_foot_us.begin());
  }
  prev_ir = ir_value;
  prev_diff = diff;

  portENTER_CRITICAL(&mux);
  ir_sum_window += (uint64_t)ir_value;
  ir_count_window++;
  portEXIT_CRITICAL(&mux);
}

void compute_ptt_window() {
  ptt_list.clear();
  for (size_t i = 0; i < rpeaks_us.size(); ++i) {
    unsigned long r = rpeaks_us[i];
    for (size_t j = 0; j < ppg_foot_us.size(); ++j) {
      if (ppg_foot_us[j] > r) {
        float ptt_ms = (ppg_foot_us[j] - r) / 1000.0f;
        if (ptt_ms > 50 && ptt_ms < 500) ptt_list.push_back(ptt_ms);
        break;
      }
    }
  }
  if (ptt_list.empty()) return;
  std::sort(ptt_list.begin(), ptt_list.end());
  float median_ptt = ptt_list[ptt_list.size()/2];
  portENTER_CRITICAL(&mux);
  PTT_ms = median_ptt;
  portEXIT_CRITICAL(&mux);
}

// ===== Confidence gating =====
bool pass_confidence_gating() {
  int valid_pairs = (int)ptt_list.size();
  float ptt_std = 0.0;
  if (ptt_list.size() > 1) {
    float mean = 0;
    for (float v : ptt_list) mean += v;
    mean /= ptt_list.size();
    float var = 0;
    for (float v : ptt_list) var += (v - mean)*(v - mean);
    var /= ptt_list.size();
    ptt_std = sqrt(var);
  }
  uint64_t ir_sum = 0; int ir_count = 0;
  float acc = 0, hr = 0;
  portENTER_CRITICAL(&mux);
  ir_sum = ir_sum_window; ir_count = ir_count_window; acc = acc_mag; hr = heartRate;
  portEXIT_CRITICAL(&mux);
  float ir_avg = (ir_count > 0) ? (float)ir_sum / ir_count : 0.0f;

  if (valid_pairs < 5) return false;
  if (ptt_std > 20.0) return false;
  if (ir_avg < 15000.0) return false;
  if (acc > 1.5) return false;
  if (hr < 40 || hr > 180) return false;
  return true;
}

// ===== Model load from SPIFFS =====
bool load_model_from_spiffs(const char* path) {
  if (!SPIFFS.begin(true)) return false;
  if (!SPIFFS.exists(path)) return false;
  File f = SPIFFS.open(path, "r");
  if (!f) return false;
  size_t size = f.size();
  std::unique_ptr<char[]> buf(new char[size + 1]);
  f.readBytes(buf.get(), size);
  buf[size] = '\0';
  f.close();

  DynamicJsonDocument doc(4096);
  auto err = deserializeJson(doc, buf.get());
  if (err) return false;

  model_features.clear();
  if (doc.containsKey("features") && doc["features"].is<JsonArray>()) {
    for (JsonVariant v : doc["features"].as<JsonArray>()) model_features.push_back(String((const char*)v.as<const char*>()));
  } else return false;

  if (doc.containsKey("sbp") && doc["sbp"].is<JsonObject>()) {
    sbp_model.intercept = doc["sbp"]["intercept"].as<float>();
    sbp_model.coefs.clear();
    for (JsonVariant v : doc["sbp"]["coefs"].as<JsonArray>()) sbp_model.coefs.push_back(v.as<float>());
    sbp_model.valid = (sbp_model.coefs.size() == model_features.size() - 1);
  } else return false;

  if (doc.containsKey("dbp") && doc["dbp"].is<JsonObject>()) {
    dbp_model.intercept = doc["dbp"]["intercept"].as<float>();
    dbp_model.coefs.clear();
    for (JsonVariant v : doc["dbp"]["coefs"].as<JsonArray>()) dbp_model.coefs.push_back(v.as<float>());
    dbp_model.valid = (dbp_model.coefs.size() == model_features.size() - 1);
  } else return false;

  return sbp_model.valid && dbp_model.valid;
}

float compute_linear(const LinearModel &m, const std::vector<float> &x) {
  if (!m.valid || x.size() != m.coefs.size()) return NAN;
  float y = m.intercept;
  for (size_t i = 0; i < m.coefs.size(); ++i) y += m.coefs[i] * x[i];
  return y;
}

// ===== FHIR builder =====
String buildFHIRBundleJson(float hr, float sbp, float dbp, float spo2, float tC, float rr, float ptt) {
  StaticJsonDocument<1024> doc;
  doc["resourceType"] = "Bundle";
  doc["type"] = "collection";
  JsonArray entry = doc.createNestedArray("entry");
auto addObservation = [&](const char* loinc, const char* display, float value, const char* unit) {
    JsonObject e = entry.createNestedObject();
    JsonObject res = e.createNestedObject("resource");
    res["resourceType"] = "Observation";
    res["status"] = "final";
    res["effectiveDateTime"] = ""; // optional: fill with ISO timestamp
    JsonObject code = res.createNestedObject("code");
    JsonArray coding = code.createNestedArray("coding");
    JsonObject c = coding.createNestedObject();
    c["system"] = "http://loinc.org";
    c["code"] = loinc;
    c["display"] = display;
    JsonObject vq = res.createNestedObject("valueQuantity");
    if (!isnan(value)) vq["value"] = value;
    else vq["value"] = nullptr;
    vq["unit"] = unit;
    JsonObject device = res.createNestedObject("device");
    device["reference"] = "Device/esp32-001";
  };

  addObservation("8867-4", "Heart rate", hr, "beats/min");
  addObservation("8480-6", "Systolic blood pressure", sbp, "mmHg");
  addObservation("8462-4", "Diastolic blood pressure", dbp, "mmHg");
  addObservation("59408-5", "Oxygen saturation", spo2, "%");
  addObservation("8310-5", "Body temperature", tC, "C");
  addObservation("9279-1", "Respiratory rate", rr, "breaths/min");
  addObservation("X-PTT", "Pulse Transit Time", ptt, "ms");

  String out;
  serializeJson(doc, out);
  return out;
}

// ===== Tasks =====
void TaskSensors(void *pvParameters) {
  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.setClock(400000);
  lcd.init(); lcd.backlight();
  particleSensor.begin();
  particleSensor.setup();
  imu.begin(Wire, 0);
  mlx.begin();
  ads1292_init();

  unsigned long lastComputePTT = millis();

  while (true) {
    unsigned long now = millis();

    int ecgVal = analogRead(ECG_PIN);
    unsigned long t_us = micros();
    process_ecg_sample(ecgVal, t_us);

    particleSensor.check();
    if (particleSensor.available()) {
      long ir = particleSensor.getIR();
      unsigned long ppg_ts = micros();
      process_ppg_sample(ir, ppg_ts);
      long red = particleSensor.getRed();
      if (ir > 0) {
        float R = (float)red / (float)ir;
        float spo2 = 110.0 - 25.0 * R;
        spo2 = constrain(spo2, 50.0, 100.0);
        portENTER_CRITICAL(&mux); SpO2 = spo2; lastPPGMicros = micros(); portEXIT_CRITICAL(&mux);
      }
    }

    ads1292_read_once();

    imu.getAGMT();
    float ax = imu.ax, ay = imu.ay, az = imu.az;
    float acc = sqrt(ax*ax + ay*ay + az*az);
    portENTER_CRITICAL(&mux); acc_mag = acc; portEXIT_CRITICAL(&mux);
    if (acc > 2.0) {
      digitalWrite(BUZZER_PIN, HIGH);
      vTaskDelay(20 / portTICK_PERIOD_MS);
      digitalWrite(BUZZER_PIN, LOW);
    }

    float tC = mlx.readObjectTempC();
    if (!isnan(tC) && tC > 20 && tC < 45) { portENTER_CRITICAL(&mux); tempC = tC; portEXIT_CRITICAL(&mux); }

    if (millis() - lastComputePTT >= 2000) {
      compute_ptt_window();
      lastComputePTT = millis();
      portENTER_CRITICAL(&mux); ir_sum_window = 0; ir_count_window = 0; portEXIT_CRITICAL(&mux);
    }

    portENTER_CRITICAL(&mux);
    float hr_disp = heartRate, spo2_disp = SpO2, sbp_disp = SBP, dbp_disp = DBP, temp_disp = tempC, rr_disp = RespRate;
    portEXIT_CRITICAL(&mux);
    lcd.clear();
    lcd.setCursor(0,0);
    lcd.printf("HR:%d RR:%d", (int)hr_disp, (int)rr_disp);
    lcd.setCursor(0,1);
    lcd.printf("BP:%d/%d S:%d T:%.1f", (int)sbp_disp, (int)dbp_disp, (int)spo2_disp, temp_disp);

    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

void TaskIoT(void *pvParameters) {
  load_model_from_spiffs("/ptt_ridge_model.json");

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { vTaskDelay(500 / portTICK_PERIOD_MS); }
  client.setServer(mqtt_server, mqtt_port);

  while (true) {
    if (!client.connected()) {
      if (!client.connect("ESP32FHIRClient")) { vTaskDelay(5000 / portTICK_PERIOD_MS); continue; }
      client.subscribe("health/cmd");
    }
    client.loop();

    portENTER_CRITICAL(&mux);
    float hr = heartRate, spo2 = SpO2, tC = tempC, rr = RespRate, ptt = PTT_ms, acc = acc_mag;
    portEXIT_CRITICAL(&mux);
std::vector<float> x;
    for (size_t i = 1; i < model_features.size(); ++i) {
      String f = model_features[i];
      if (f == "ptt_median") x.push_back(ptt);
      else if (f == "hr_median") x.push_back(hr);
      else if (f == "temp") x.push_back(tC);
      else if (f == "age") x.push_back(30.0);
      else if (f == "bmi") x.push_back(25.0);
      else x.push_back(0.0);
    }

    float sbp_est = NAN, dbp_est = NAN;
    if (sbp_model.valid && dbp_model.valid && x.size() == sbp_model.coefs.size()) {
      sbp_est = compute_linear(sbp_model, x);
      dbp_est = compute_linear(dbp_model, x);
    }

    bool ok = pass_confidence_gating();
    String fhir;
    if (ok && !isnan(sbp_est) && !isnan(dbp_est)) {
      portENTER_CRITICAL(&mux); SBP = sbp_est; DBP = dbp_est; portEXIT_CRITICAL(&mux);
      fhir = buildFHIRBundleJson(hr, sbp_est, dbp_est, spo2, tC, rr, ptt);
    } else {
      fhir = buildFHIRBundleJson(hr, NAN, NAN, spo2, tC, rr, ptt);
    }

    String encrypted = encryptGCM(fhir);
    if (encrypted.length() > 0) client.publish(mqtt_topic, encrypted.c_str());

    vTaskDelay(2000 / portTICK_PERIOD_MS);
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(BTN1, INPUT_PULLUP);
  pinMode(BTN2, INPUT_PULLUP);
  SPIFFS.begin(true);
  xTaskCreatePinnedToCore(TaskSensors, "Sensors", 20000, NULL, 1, NULL, 1);
  xTaskCreatePinnedToCore(TaskIoT, "IoT", 20000, NULL, 1, NULL, 0);
}

void loop() { vTaskDelay(1000 / portTICK_PERIOD_MS); }
