# File: dashboard_fhir_final.py
# TLS optional: this script subscribes to MQTT, decrypts AES-GCM hex payloads,
# parses FHIR bundles, and plots live vitals. Requires: paho-mqtt, pycryptodome, matplotlib

import json
from collections import deque
from datetime import datetime
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import ssl
import os

BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "health/fhir"
CLIENT_ID = "DashboardFHIRClient"

# AES key must match ESP32
AES_KEY = bytes([
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
])

max_points = 120
time_buf = deque(maxlen=max_points)
hr_buf = deque(maxlen=max_points)
sbp_buf = deque(maxlen=max_points)
dbp_buf = deque(maxlen=max_points)
spo2_buf = deque(maxlen=max_points)
temp_buf = deque(maxlen=max_points)
rr_buf = deque(maxlen=max_points)
ptt_buf = deque(maxlen=max_points)

plt.ion()
fig, axs = plt.subplots(3, 1, figsize=(12, 9))
fig.suptitle("ESP32 Health Monitor Secure Dashboard", fontsize=14)

def decrypt_gcm_hex(hexdata: str) -> str:
    try:
        if not isinstance(hexdata, str):
            raise ValueError("Payload not a string")
        if len(hexdata) < 56:
            raise ValueError("Encrypted payload too short")
        iv_hex = hexdata[0:24]
        tag_hex = hexdata[-32:]
        ct_hex = hexdata[24:-32]
        iv = bytes.fromhex(iv_hex)
        ct = bytes.fromhex(ct_hex) if ct_hex else b''
        tag = bytes.fromhex(tag_hex)
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ct, tag)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Decrypt error: {e}")

def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT broker, subscribing to topic:", TOPIC)
    client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    try:
        encrypted_hex = msg.payload.decode('utf-8')
        decrypted = decrypt_gcm_hex(encrypted_hex)
        fhir = json.loads(decrypted)
        now = datetime.now().strftime("%H:%M:%S")
        time_buf.append(now)

        hr = sbp = dbp = spo2 = temp = rr = ptt = None
        for entry in fhir.get("entry", []):
            res = entry.get("resource", {})
            code = res.get("code", {}).get("coding", [{}])[0].get("code", "")
            val = res.get("valueQuantity", {}).get("value", None)
            if code == "8867-4": hr = val
            elif code == "8480-6": sbp = val
            elif code == "8462-4": dbp = val
            elif code == "59408-5": spo2 = val
            elif code == "8310-5": temp = val
            elif code == "9279-1": rr = val
            elif code == "X-PTT": ptt = val

        hr_buf.append(hr if hr is not None else (hr_buf[-1] if hr_buf else 0))
        sbp_buf.append(sbp if sbp is not None else (sbp_buf[-1] if sbp_buf else 0))
        dbp_buf.append(dbp if dbp is not None else (dbp_buf[-1] if dbp_buf else 0))
        spo2_buf.append(spo2 if spo2 is not None else (spo2_buf[-1] if spo2_buf else 0))
        temp_buf.append(temp if temp is not None else (temp_buf[-1] if temp_buf else 0))
        rr_buf.append(rr if rr is not None else (rr_buf[-1] if rr_buf else 0))
        ptt_buf.append(ptt if ptt is not None else (ptt_buf[-1] if ptt_buf else 0))

        print(f"[{now}] HR:{hr} SBP:{sbp} DBP:{dbp} SpO2:{spo2} Temp:{temp} RR:{rr} PTT:{ptt}")

        axs[0].clear()
        axs[0].plot(time_buf, hr_buf, 'r-', label='Heart Rate (bpm)')
        axs[0].plot(time_buf, sbp_buf, 'b-', label='SBP (mmHg)')
        axs[0].plot(time_buf, dbp_buf, 'c-', label='DBP (mmHg)')
        axs[0].legend(loc='upper left'); axs[0].set_title("Heart Rate & Blood Pressure")
        axs[0].tick_params(axis='x', rotation=45)

        axs[1].clear()
        axs[1].plot(time_buf, spo2_buf, 'g-', label='SpO2 (%)')
        axs[1].plot(time_buf, temp_buf, 'm-', label='Temp (C)')
        axs[1].legend(loc='upper left'); axs[1].set_title("SpO2 & Temperature")
        axs[1].tick_params(axis='x', rotation=45)
axs[2].clear()
        axs[2].plot(time_buf, rr_buf, 'k-', label='Respiratory Rate (breaths/min)')
        axs[2].plot(time_buf, ptt_buf, 'y-', label='PTT (ms)')
        axs[2].legend(loc='upper left'); axs[2].set_title("Respiratory Rate & PTT")
        axs[2].tick_params(axis='x', rotation=45)

        plt.tight_layout()
        plt.pause(0.01)

    except Exception as e:
        print("Error processing message:", e)

def main():
    client = mqtt.Client(client_id=CLIENT_ID)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT, 60)
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("Exiting dashboard")

if __name__ == "main":
    main()
