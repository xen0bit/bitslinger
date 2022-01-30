import websocket
import _thread
import time

def unpackBitSlinger(message):
    segments = message.split("\n")
    if len(segments) >= 2:
        packetUuid = segments[0]
        packetPayload = bytes.fromhex(segments[1])
        return packetUuid, packetPayload

def packBitSlinger(packetUuid, packetPayload):
    return packetUuid + "\n" + packetPayload.hex() + "\n"

def modifyPayload(packetPayload):
    return packetPayload.replace(b'world', b'remy!')

def on_message(ws, message):
    packetUuid, packetPayload = unpackBitSlinger(message)
    newPacketPayload = modifyPayload(packetPayload)
    newMessage = packBitSlinger(packetUuid, newPacketPayload)
    ws.send(newMessage)

def on_error(ws, error):
    print(error)

def on_close(ws, close_status_code, close_msg):
    print("### closed ###")

def on_open(ws):
    print("Connected")

if __name__ == "__main__":
    #websocket.enableTrace(True)
    ws = websocket.WebSocketApp("ws://127.0.0.1:9393/bitslinger",
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)
    try:
        ws.run_forever()
    except:
        ws.close()