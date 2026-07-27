"""HTTP endpoints for packet-capture operations."""

from http import HTTPStatus

from flask import Blueprint, current_app, jsonify, request

from app.services.capture_service import CaptureService

capture_controller = Blueprint(
    "capture_controller",
    __name__,
    url_prefix="/api/v1/capture",
)

capture_service = CaptureService()


@capture_controller.post("/start")
def start_capture():
    """Start a new packet-capture session."""
    body = request.get_json(silent=True) or {}

    interface = body.get(
        "interface",
        current_app.config["CAPTURE_INTERFACE"],
    )

    if (
        not isinstance(interface, str)
        or not interface.strip()
        or interface == "not-configured"
    ):
        return jsonify(
            {
                "error": "A valid capture interface is required.",
            }
        ), HTTPStatus.BAD_REQUEST

    capture = capture_service.start(interface.strip())

    if capture is None:
        return jsonify(
            {
                "error": "A capture session is already running.",
            }
        ), HTTPStatus.CONFLICT

    return jsonify(
        {
            "message": "Capture start accepted.",
            "capture": capture,
        }
    ), HTTPStatus.ACCEPTED


@capture_controller.post("/stop")
def stop_capture():
    """Stop the current packet-capture session."""
    capture = capture_service.stop()

    if capture is None:
        return jsonify(
            {
                "error": "No capture session is currently running.",
            }
        ), HTTPStatus.CONFLICT

    return jsonify(
        {
            "message": "Capture stopped successfully.",
            "capture": capture,
        }
    ), HTTPStatus.OK

@capture_controller.get("/status")
def get_capture_status():
    """Return the current packet-capture status."""
    capture = capture_service.get_status()

    return jsonify(
        {
            "capture": capture,
        }
    ), HTTPStatus.OK