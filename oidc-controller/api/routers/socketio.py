import socketio  # For using websockets
import logging
import time

logger = logging.getLogger(__name__)

connections = {}
message_buffers = {}
buffer_timeout = 60  # Timeout in seconds

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
sio_app = socketio.ASGIApp(socketio_server=sio, socketio_path="/ws/socket.io")


@sio.event
async def connect(sid, socket):
    logger.info(f">>> connect : sid={sid}")


@sio.event
async def initialize(sid, data):
    global connections, message_buffers
    pid = data.get("pid")
    connections[pid] = sid
    # Initialize buffer if it doesn't exist
    if pid not in message_buffers:
        message_buffers[pid] = []


@sio.event
async def disconnect(sid):
    global connections, message_buffers
    logger.info(f">>> disconnect : sid={sid}")
    # Find the pid associated with the sid
    pid = next((k for k, v in connections.items() if v == sid), None)
    if pid:
        # Remove pid from connections
        del connections[pid]


async def buffered_emit(event, data, to_pid=None):
    global connections, message_buffers

    connections = connections_reload()
    sid = connections.get(to_pid)
    logger.debug(f"sid: {sid} found for pid: {to_pid}")

    if sid:
        try:
            await sio.emit(event, data, room=sid)
        except:
            # If send fails, buffer the message
            buffer_message(to_pid, event, data)
    else:
        # Buffer the message if the target is not connected
        buffer_message(to_pid, event, data)


def buffer_message(pid, event, data):
    global message_buffers
    current_time = time.time()
    if pid not in message_buffers:
        message_buffers[pid] = []
    # Add message with timestamp and event name
    message_buffers[pid].append((event, data, current_time))
    # Clean up old messages
    message_buffers[pid] = [
        (msg_event, msg_data, timestamp)
        for msg_event, msg_data, timestamp in message_buffers[pid]
        if current_time - timestamp <= buffer_timeout
    ]


@sio.event
async def fetch_buffered_messages(sid, pid):
    global message_buffers
    current_time = time.time()
    if pid in message_buffers:
        # Filter messages that are still valid (i.e., within the buffer_timeout)
        valid_messages = [
            (msg_event, msg_data, timestamp)
            for msg_event, msg_data, timestamp in message_buffers[pid]
            if current_time - timestamp <= buffer_timeout
        ]
        # Emit each valid message
        for event, data, _ in valid_messages:
            await sio.emit(event, data, room=sid)
        # Reassign the valid_messages back to message_buffers[pid] to clean up old messages
        message_buffers[pid] = valid_messages


def connections_reload():
    global connections
    return connections
