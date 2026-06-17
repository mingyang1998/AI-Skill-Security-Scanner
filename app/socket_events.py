import logging
from flask_socketio import emit, join_room, leave_room

logger = logging.getLogger(__name__)


def register_socket_events(sio):
    @sio.on('connect')
    def handle_connect():
        logger.info('Client connected')

    @sio.on('disconnect')
    def handle_disconnect():
        logger.info('Client disconnected')

    @sio.on('join_task')
    def handle_join_task(data):
        task_id = data.get('task_id')
        if task_id:
            join_room(f'task_{task_id}')
            logger.info(f'Client joined room: task_{task_id}')

    @sio.on('leave_task')
    def handle_leave_task(data):
        task_id = data.get('task_id')
        if task_id:
            leave_room(f'task_{task_id}')
            logger.info(f'Client left room: task_{task_id}')


def emit_scan_progress(sio, task_id, progress, status, **extra):
    sio.emit('scan_progress', {
        'task_id': task_id,
        'progress': progress,
        'status': status,
        **extra
    }, room=f'task_{task_id}')
