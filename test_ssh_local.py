import socketio
import threading
import sys

sio = socketio.Client()

@sio.event
def connect():
    print("[*] 本地连接成功，发送 ssh_proxy")
    sio.emit('ssh_proxy')

@sio.event
def ssh_ready(data):
    print(f"[*] ssh_ready: {data}")

@sio.event
def ssh_data(data):
    sys.stdout.buffer.write(data['data'].encode('latin1'))
    sys.stdout.flush()

def forward_input():
    while True:
        try:
            chunk = sys.stdin.buffer.read(4096)
            if not chunk:
                break
            sio.emit('ssh_data', {'data': chunk.decode('latin1')})
        except KeyboardInterrupt:
            break
    sio.disconnect()

threading.Thread(target=forward_input, daemon=True).start()

# 连接到本地后端
sio.connect('http://127.0.0.1:8083', transports=['websocket'], socketio_path='/socket.io')
sio.wait()
