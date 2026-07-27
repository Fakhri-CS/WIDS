"""HTTP endpoints for observed wireless access points."""

from http import HTTPStatus

from flask import Blueprint, jsonify

from app.services.access_point_service import AccessPointService

access_point_controller = Blueprint(
    "access_point_controller",
    __name__,
    url_prefix="/api/v1/access-points",
)

access_point_service = AccessPointService()


@access_point_controller.get("")
def get_access_points():
    """Return all wireless access points observed by the WIDS sensor."""
    access_points = access_point_service.get_all()

    return jsonify(
        {
            "access_points": access_points,
            "count": len(access_points),
        }
    ), HTTPStatus.OK
