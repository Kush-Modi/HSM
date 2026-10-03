#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/md.h"

// =====================================================
// CONFIGURATION
// =====================================================

const char* WIFI_SSID = "Kush";
const char* WIFI_PASSWORD = "qwerty123";

const char* GATEWAY_URL =
    "http://192.168.137.2:5000";

const char* DEVICE_ID =
    "ESP32-DEVKIT";

const char* DEVICE_SECRET =
    "QI-HSM-ESP32-DEVKIT-SECRET";

const unsigned long AUTH_INTERVAL =
    30000;


// =====================================================
// HARDWARE FINGERPRINT
// =====================================================

String getHardwareFingerprint()
{
    uint64_t mac = ESP.getEfuseMac();

    uint32_t macHigh = (uint32_t)(mac >> 32);
    uint32_t macLow  = (uint32_t)(mac & 0xFFFFFFFF);

    uint32_t chipInfo =
        ((uint32_t)ESP.getChipModel()[0] << 24) ^
        ((uint32_t)ESP.getChipRevision() << 16) ^
        ((uint32_t)ESP.getChipCores() << 8) ^
        (uint32_t)(ESP.getFlashChipSize() / (1024 * 1024));

    // Quantum-inspired mixing
    uint32_t value =
        macHigh ^
        macLow ^
        chipInfo;

    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;

    char fingerprint[9];

    snprintf(
        fingerprint,
        sizeof(fingerprint),
        "%08X",
        value
    );

    return String(fingerprint);
}


// =====================================================
// SHA-256
// =====================================================

String sha256(String input)
{
    byte hash[32];

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(
            MBEDTLS_MD_SHA256
        );

    mbedtls_md_setup(
        &ctx,
        info,
        0
    );

    mbedtls_md_starts(&ctx);

    mbedtls_md_update(
        &ctx,
        (const unsigned char*)input.c_str(),
        input.length()
    );

    mbedtls_md_finish(
        &ctx,
        hash
    );

    mbedtls_md_free(&ctx);

    String result;

    for (int i = 0; i < 32; i++)
    {
        if (hash[i] < 16)
            result += "0";

        result += String(
            hash[i],
            HEX
        );
    }

    return result;
}


// =====================================================
// HMAC-SHA256
// =====================================================

String calculateHMAC(
    String message,
    String key
)
{
    byte result[32];

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t* info =
        mbedtls_md_info_from_type(
            MBEDTLS_MD_SHA256
        );

    mbedtls_md_setup(
        &ctx,
        info,
        1
    );

    mbedtls_md_hmac_starts(
        &ctx,
        (const unsigned char*)key.c_str(),
        key.length()
    );

    mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)message.c_str(),
        message.length()
    );

    mbedtls_md_hmac_finish(
        &ctx,
        result
    );

    mbedtls_md_free(&ctx);

    String output;

    for (int i = 0; i < 32; i++)
    {
        if (result[i] < 16)
            output += "0";

        output += String(
            result[i],
            HEX
        );
    }

    return output;
}


// =====================================================
// WIFI
// =====================================================

bool connectWiFi()
{
    WiFi.mode(WIFI_STA);

    WiFi.begin(
        WIFI_SSID,
        WIFI_PASSWORD
    );

    Serial.print(
        "Connecting to gateway"
    );

    int attempts = 0;

    while (
        WiFi.status() != WL_CONNECTED &&
        attempts < 30
    )
    {
        delay(500);

        Serial.print(".");

        attempts++;
    }

    Serial.println();

    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.println(
            "[SUCCESS] Wi-Fi connected"
        );

        Serial.print(
            "ESP32 IP: "
        );

        Serial.println(
            WiFi.localIP()
        );

        Serial.print(
            "Gateway IP: "
        );

        Serial.println(
            WiFi.gatewayIP()
        );

        return true;
    }

    Serial.println(
        "[ERROR] Wi-Fi connection failed"
    );

    return false;
}


// =====================================================
// REGISTER
// =====================================================

bool registerDevice(
    String fingerprint
)
{
    HTTPClient http;

    String url =
        String(GATEWAY_URL) +
        "/register";

    http.begin(url);

    http.addHeader(
        "Content-Type",
        "application/json"
    );

    JsonDocument doc;

    doc["device_id"] =
        DEVICE_ID;

    doc["fingerprint"] =
        fingerprint;

    String body;

    serializeJson(
        doc,
        body
    );

    Serial.println();

    Serial.println(
        "[REGISTER] Sending device registration..."
    );

    int httpCode =
        http.POST(body);

    Serial.print(
        "[REGISTER] HTTP "
    );

    Serial.println(
        httpCode
    );

    String response =
        http.getString();

    Serial.println(
        "[REGISTER] Gateway response:"
    );

    Serial.println(
        response
    );

    http.end();

    return (
        httpCode == 200
    );
}


// =====================================================
// REQUEST CHALLENGE
// =====================================================

String requestChallenge()
{
    HTTPClient http;

    String url =
        String(GATEWAY_URL) +
        "/challenge?device_id=" +
        DEVICE_ID;

    http.begin(url);

    Serial.println();

    Serial.println(
        "[AUTH] Requesting challenge..."
    );

    int httpCode =
        http.GET();

    if (httpCode != 200)
    {
        Serial.print(
            "[ERROR] Challenge HTTP: "
        );

        Serial.println(
            httpCode
        );

        http.end();

        return "";
    }

    String response =
        http.getString();

    http.end();

    JsonDocument doc;

    DeserializationError error =
        deserializeJson(
            doc,
            response
        );

    if (error)
    {
        Serial.println(
            "[ERROR] Invalid challenge JSON"
        );

        return "";
    }

    String challenge =
        doc["challenge"].as<String>();

    Serial.print(
        "[AUTH] Challenge: "
    );

    Serial.println(
        challenge
    );

    return challenge;
}


// =====================================================
// AUTHENTICATE
// =====================================================

bool authenticate(
    String fingerprint,
    String challenge
)
{
    // Derive device-specific key
    String keyMaterial =
        String(DEVICE_SECRET) +
        fingerprint;

    String hmacKey =
        sha256(keyMaterial);

    // Challenge-bound message
    String message =
        challenge +
        "|" +
        DEVICE_ID +
        "|" +
        fingerprint;

    String response =
        calculateHMAC(
            message,
            hmacKey
        );

    int rssi =
        WiFi.RSSI();

    Serial.println();

    Serial.println(
        "[AUTH] Authentication material generated"
    );

    Serial.print(
        "[AUTH] HMAC: "
    );

    Serial.println(
        response
    );

    Serial.print(
        "[BEHAVIOR] RSSI: "
    );

    Serial.print(
        rssi
    );

    Serial.println(
        " dBm"
    );

    HTTPClient http;

    String url =
        String(GATEWAY_URL) +
        "/authenticate";

    http.begin(url);

    http.addHeader(
        "Content-Type",
        "application/json"
    );

    JsonDocument doc;

    doc["device_id"] =
        DEVICE_ID;

    doc["fingerprint"] =
        fingerprint;

    doc["response"] =
        response;

    doc["rssi"] =
        rssi;

    String body;

    serializeJson(
        doc,
        body
    );

    int httpCode =
        http.POST(body);

    String gatewayResponse =
        http.getString();

    Serial.print(
        "[AUTH] Gateway HTTP: "
    );

    Serial.println(
        httpCode
    );

    Serial.println(
        "[AUTH] Gateway response:"
    );

    Serial.println(
        gatewayResponse
    );

    http.end();

    JsonDocument result;

    DeserializationError error =
        deserializeJson(
            result,
            gatewayResponse
        );

    if (error)
    {
        return false;
    }

    bool authenticated =
        result["authenticated"] |
        false;

    if (authenticated)
    {
        Serial.println();

        Serial.println(
            "================================"
        );

        Serial.println(
            "   AUTHENTICATION SUCCESSFUL"
        );

        Serial.println(
            "   DEVICE TRUSTED"
        );

        Serial.println(
            "================================"
        );

        return true;
    }

    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "   AUTHENTICATION FAILED"
    );

    Serial.println(
        "   SECURITY EVENT DETECTED"
    );

    Serial.println(
        "================================"
    );

    return false;
}


// =====================================================
// SETUP
// =====================================================

void setup()
{
    Serial.begin(9600);

    delay(1500);

    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "       QI-HSM ESP32 NODE"
    );

    Serial.println(
        "================================"
    );

    if (!connectWiFi())
    {
        return;
    }

    String fingerprint =
        getHardwareFingerprint();

    Serial.println();

    Serial.print(
        "[HARDWARE] Fingerprint: 0x"
    );

    Serial.println(
        fingerprint
    );

    // Registration
    registerDevice(
        fingerprint
    );

    delay(1000);

    // Initial authentication
    String challenge =
        requestChallenge();

    if (challenge != "")
    {
        authenticate(
            fingerprint,
            challenge
        );
    }
}


// =====================================================
// PERIODIC AUTHENTICATION
// =====================================================

unsigned long lastAuthentication = 0;


void loop()
{
    if (
        WiFi.status() != WL_CONNECTED
    )
    {
        Serial.println(
            "[WARNING] Wi-Fi disconnected"
        );

        connectWiFi();

        delay(1000);

        return;
    }

    if (
        millis() - lastAuthentication
        >= AUTH_INTERVAL
    )
    {
        lastAuthentication =
            millis();

        Serial.println();

        Serial.println(
            "================================"
        );

        Serial.println(
            "   PERIODIC AUTHENTICATION"
        );

        Serial.println(
            "================================"
        );

        String fingerprint =
            getHardwareFingerprint();

        String challenge =
            requestChallenge();

        if (challenge == "")
        {
            Serial.println(
                "[ERROR] No challenge received"
            );

            return;
        }

        authenticate(
            fingerprint,
            challenge
        );
    }

    delay(100);
}