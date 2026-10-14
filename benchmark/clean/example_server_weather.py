"""Clean benchmark fixture: fictional weather service with external client access."""

import logging

logger = logging.getLogger(__name__)


def get_forecast(city, weather_client):
    """Return a forecast from an injected client without exposing request metadata."""
    try:
        forecast = weather_client.forecast(city=city, days=3)
    except TimeoutError:
        logger.warning("weather lookup timed out for city lookup")
        return {"ok": False, "error": "weather service temporarily unavailable"}

    return {
        "ok": True,
        "city": city,
        "summary": forecast["summary"],
        "temperature_c": forecast["temperature_c"],
    }
