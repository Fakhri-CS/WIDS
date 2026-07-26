"""HTTP endpoints for observed wireless devices."""

from http import HTTPStatus

from flask import Blueprint, jsonify

from app.services.device_service import DeviceService


device_controller = Blueprint(
    "device_controller",
    __name__,
    url_prefix="/api/v1/devices",
)

device_service = DeviceService()


@device_controller.get("")
def get_devices():
    """Return all wireless devices observed by the WIDS sensor."""
    devices = device_service.get_all()

    return jsonify(
        {
            "devices": devices,
            "count": len(devices),
        }
    ), HTTPStatus.OK
