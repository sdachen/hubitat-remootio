/**
 *
 *  Hubitat Remootio integration
 *  Copyright 2022 Scott Deeann Chen 
 *
 */ 

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field

import java.util.concurrent.ConcurrentHashMap
import java.util.Random

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.binary.Base64

metadata {
    definition (name: "Remootio Gate Controller", namespace: "sdachen.remootio", author: "Scott Deeann Chen") {
        capability "GarageDoorControl"
        command "trigger"
        command "query"
        attribute "deviceActive", "boolean"
    }

    preferences {
        input name: "remootioIpAddress", type: "text", title: "IP Address", required: true
        input name: "remootioApiSecretKey", type: "text", title: "API Secret Key", required: true
        input name: "remootioApiAuthKey", type: "text", title: "API Auth Key", required: true
        input name: "enableLogging", type: "bool", title: "Enable Debugging Logging"
    }
}

@Field static Map sharedState = new java.util.concurrent.ConcurrentHashMap()

// Hubitat device methods
void installed() {
    if (enableLogging) log.debug "installed()"
    // Ping every minute, using quartz cron
    schedule("0 * * ? * *", ping)
}

void updated() {
    if (enableLogging) log.debug "updated()"
    establishConnection()
}

// Connection management
void establishConnection() {
    if (enableLogging) log.debug "establishConnection()"
    interfaces.webSocket.close()
    resetState()
    // Do not use the ping provided by webSocket due to Remootio not returning the ping.
    // Implement our own ping and reconnect mechanism. This implementation drops the connection every 100 years.
    interfaces.webSocket.connect("ws://${remootioIpAddress}:8080", pingInterval: 86400*365*100)
    sendAuth()
}

void ping() {
    if (enableLogging) log.debug "ping()"
    sharedState["receivedPong"] = false
    sendPing()
    // 30 seconds pong timeout
    runIn(30, checkPong)
}

void checkPong() {
    if (enableLogging) log.debug "checkPong()"
    if (!sharedState["receivedPong"]) {
        log.info "Connection lost, reconnecting."
        establishConnection()
    }
}

// Hubitat commands
void restart() {
    if (enableLogging) log.debug "restart()"
    sendRestart()
}

void open() {
    if (enableLogging) log.debug "open()"
    sendOpen()
}


void close() {
    if (enableLogging) log.debug "close()"
    sendClose()
}

void trigger() {
    if (enableLogging) log.debug "trigger()"
    sendTrigger()
}

void query() {
    if (enableLogging) log.debug "query()"
    sendQuery()
}

// Hubitat device state management methods
void resetState() {
    if (enableLogging) log.debug "resetState()"
    sendEvent(name: "deviceActive", value: false, descriptionText: "Challenge Received", isStateChange: false)
    sharedState["sessionkey"] = ""
    sharedState["actionId"] = 0
    sharedState["receivedPong"] = false
}

void updateDoorState(String state, String description, boolean isStateChange) {
    // door - ENUM ["unknown", "open", "closing", "closed", "opening"]
    if (enableLogging) log.debug "updateDoorState(): ${state}, ${description}, ${isStateChange}"
    switch(state) {
        case "open":
        case "closing":
        case "closed":
        case "opening":
            sendEvent(name: "door", value: state, descriptionText: description, isStateChange: isStateChange)
            break;
        default:
            sendEvent(name: "door", value: "unknown", descriptionText: description, isStateChange: isStateChange)
            break;
    }
}

int getNextActionId() {
    sharedState["actionId"] = (sharedState["actionId"] + 1) % 0x7FFFFFFF
    return sharedState["actionId"]
}

// Websocket incoming data processing methods
void parse(String messageJson) {
    if (enableLogging) log.debug "parse(): ${messageJson}"

    def slurper = new groovy.json.JsonSlurper()
    def message = slurper.parseText(messageJson)

    if (message.type) {
        switch(message.type) { 
            case "ENCRYPTED":
                def data = JsonOutput.toJson(message.data)
                            
                if (!isValidMac(message)) {
                    log.error("Message tampered!")
                    break;
                }

                String originalMessageJson = decrypt(message.data.payload, message.data.iv)
                parse(originalMessageJson)
                break;

            case "ERROR": 
                if (enableLogging) "ERROR: ${message}"
                break;

            case "PONG":
                if (enableLogging) log.debug "Received PONG!"
                sharedState["receivedPong"] = true
                break;

            case "CHALLENGE":
                sharedState["sessionkey"] = message.challenge.sessionKey
                sharedState["actionId"] = message.challenge.initialActionId
                sendQuery()
                sendEvent(name: "deviceActive", value: true, descriptionText: "Challenge Received", isStateChange: false)
                break;

            default:
                if (enableLogging) log.debug "Logic for ${message.type} not implemented."
                break;
        } 
    }

    if (message.response) {
        updateDoorState(message.response.state, "Remootio response to action ${message.response.type}.", false)
    }

    if (message.event) {
        updateDoorState(message.event.state, "Remootio initated update event.", false)
    }
}

void webSocketStatus(String message) {
    if (enableLogging) log.debug "webSocketStatus() received ${message}"
}

// Remootio interfacing methods
void encryptSend(String dataJson) {
    if (enableLogging) log.debug "encryptSend() ${dataJson}"
    interfaces.webSocket.sendMessage(encrypt(dataJson))
}

void sendRestart() {
    def data = [action: [type: "RESTART", id: getNextActionId()]]
    def dataJson = JsonOutput.toJson(data)
    encryptSend(dataJson)
}

void sendAuth() {
    def data = [type: "AUTH"]
    interfaces.webSocket.sendMessage(JsonOutput.toJson(data))
}

void sendOpen() {
    def data = [action: [type: "OPEN", id: getNextActionId()]]
    def dataJson = JsonOutput.toJson(data)
    encryptSend(dataJson)
}

void sendClose() {
    def data = [action: [type: "CLOSE", id: getNextActionId()]]
    def dataJson = JsonOutput.toJson(data)
    encryptSend(dataJson)
}

void sendTrigger() {
    def data = [action: [type: "TRIGGER", id: getNextActionId()]]
    def dataJson = JsonOutput.toJson(data)
    encryptSend(dataJson)
}

void sendQuery() {
    data = [action: [type: "QUERY", id: getNextActionId()]]
    def dataJson = JsonOutput.toJson(data)
    encryptSend(dataJson)
}

void sendPing() {
    def data = [type: "PING"]
    interfaces.webSocket.sendMessage(JsonOutput.toJson(data))
}

// Data encryption & decryption methods
String decrypt(String payload, String iv) {
    byte[] key = sharedState["sessionkey"] ? Base64.decodeBase64(sharedState["sessionkey"]) : hexStringToByteArray(remootioApiSecretKey)
    IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decodeBase64(iv))
    SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES")

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)

    return new String(cipher.doFinal(Base64.decodeBase64(payload)))
}

String encrypt(String messageJson) {
    // Generate random IV
    Random random = new Random();
    byte[] randomBytes = new byte[16];
    random.nextBytes(randomBytes);
    String iv = Base64.encodeBase64String(randomBytes)

    // Build Cipher
    IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decodeBase64(iv));
    SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.decodeBase64(sharedState["sessionkey"]), "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

    // Build message
    String payload = Base64.encodeBase64String(cipher.doFinal(messageJson.getBytes()))

    def data = [iv: iv, payload: payload]
    def dataJson = JsonOutput.toJson(data)
    def mac = computeMac(dataJson)

    def encryptedMessage = [type: "ENCRYPTED", data: data, mac: mac]

    return JsonOutput.toJson(encryptedMessage)
}

String computeMac(String dataJson) {
    Mac mac = Mac.getInstance("HmacSHA256")
    SecretKeySpec secretKeySpec = new SecretKeySpec(hexStringToByteArray(remootioApiAuthKey), "HmacSHA256")
    mac.init(secretKeySpec)
    return Base64.encodeBase64String(mac.doFinal(dataJson.getBytes()))
}

boolean isValidMac(Object response) {
    def dataJson = JsonOutput.toJson(response.data)
    def mac = computeMac(dataJson)

    return mac == response.mac
}

// Utility methods
byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}
