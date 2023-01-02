/**
 *
 *  Hubitat Remootio integration
 *  Copyright 2022 Scott Deeann Chen 
 *
 */ 

import groovy.json.JsonSlurper
import groovy.json.JsonOutput

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import javax.crypto.spec.IvParameterSpec
import javax.crypto.Cipher

import java.util.Random

metadata {
    definition (name: "Remootio Gate Controller", namespace: "sdachen.remootio", author: "Scott Deeann Chen") {
        capability "GarageDoorControl"
        command "trigger"
    }

    preferences {
        input name: "remootioIpAddress", type: "text", title: "IP Address", required: true
        input name: "remootioApiSecretKey", type: "text", title: "API Secret Key", required: true
        input name: "remootioApiAuthKey", type: "text", title: "API Auth Key", required: true
        input name: "enableLogging", type: "bool", title: "Enable Debugging Logging"
    }
}

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
    clearState()
    interfaces.webSocket.close()
    // Do not use the ping provided by webSocket due to Remootio not returning the ping.
    // Implement our own ping and reconnect mechanism.
    interfaces.webSocket.connect("ws://${remootioIpAddress}:8080", pingInterval: 86400)
    sendAuth()
}

void ping() {
    if (enableLogging) log.debug "ping()"
    atomicState.receivedPong = false
    sendPing()
    // 30 seconds pong timeout
    runIn(30, checkPong)
}

void checkPong() {
    if (enableLogging) log.debug "checkPong()"
    if (!atomicState.receivedPong) {
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

// Hubitat device state management methods
void clearState() {
    if (enableLogging) log.debug "clearState()"
    state.sessionKey = null
    state.actionId = null
    state.connectionActive = false
    atomicState.receivedPong = false
}

void updateState(String state, String description, boolean isStateChange) {
    // door - ENUM ["unknown", "open", "closing", "closed", "opening"]
    if (enableLogging) log.debug "updateState(): ${state}, ${description}, ${isStateChange}"
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
    state.actionId = (state.actionId + 1) % 0x7FFFFFFF
    return state.actionId
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
                atomicState.receivedPong = true
                break;

            case "CHALLENGE":
                state.sessionKey = message.challenge.sessionKey
                state.actionId = message.challenge.initialActionId
                sendQuery()
                state.connectionActive = true
                break;

            default:
                 if (enableLogging) log.debug "Logic for ${message.type} not implemented."
                break;
        } 
    }

    if (message.response) {
        updateState(message.response.state, "Remootio response to action ${message.response.type}.", false)
    }

    if (message.event) {
        updateState(message.event.state, "Remootio initated update event.", false)
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
    byte[] key = state.sessionKey ? Base64.decodeBase64(state.sessionKey) : hexStringToByteArray(remootioApiSecretKey)
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
    SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.decodeBase64(state.sessionKey), "AES");
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
