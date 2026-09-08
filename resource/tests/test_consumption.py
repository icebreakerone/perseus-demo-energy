"""
The endpoint answers for the window it was asked for.

Until now it returned the same 100 readings from February 2012 whatever `from` and
`to` said, which left a CAP unable to run its registered calculation: the grid
intensity series its own scheme requires does not reach back that far. These cover
the window actually being honoured, and the shape of what comes back.
"""

import datetime
import json
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from tests import client_certificate, ROOT_DIR  # noqa
from api.main import app, DEMO_METER_ID, UNCOMPRESSED_WINDOW
from api import conf, consumption, models

client = TestClient(app)

HALF_HOURS_PER_DAY = 48


@pytest.fixture
def mock_check_token(mocker):
    return mocker.patch("api.main.auth.check_token")


@pytest.fixture
def authorised(monkeypatch, mocker, mock_check_token):
    """
    A caller that gets past mTLS and the token check, with provenance stubbed. What
    is under test here is the data, not the signing.
    """
    monkeypatch.setattr(
        conf, "SIGNING_ROOT_CA_CERTIFICATE", f"{ROOT_DIR}/fixtures/test-suite-cert.pem"
    )
    monkeypatch.setattr(
        conf, "SIGNING_BUNDLE", f"{ROOT_DIR}/fixtures/test-suite-bundle.pem"
    )
    mock_check_token.return_value = (
        {"sub": "account123", "scp": [conf.ENERGY_CONSUMPTION_LICENSE_URL]},
        {"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    with open(f"{ROOT_DIR}/fixtures/test-suite-key.pem") as handle:
        key = serialization.load_pem_private_key(handle.read().encode(), password=None)
    mocker.patch("api.provenance.get_key", return_value=key)
    records = mocker.patch("api.provenance.create_provenance_records")
    records.return_value = {}

    pem, _, _, _ = client_certificate(
        roles=[conf.PROVIDER_ROLE],
        member="https://directory.ib1.org/member/123456",
        add_application=True,
    )
    return {
        "Authorization": "Bearer token",
        "x-amzn-mtls-clientcert-leaf": quote(pem),
    }, records


def get(headers, measure="import", meter=DEMO_METER_ID, **params):
    query = "&".join(f"{key}={value}" for key, value in params.items())
    return client.get(f"/datasources/{meter}/{measure}?{query}", headers=headers)


# ---------------------------------------------------------------------------
# The window is honoured
# ---------------------------------------------------------------------------


def test_readings_cover_the_requested_window(authorised):
    """The reported bug: from and to were parsed and then ignored."""
    headers, _ = authorised
    response = get(headers, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-08T00:00:00Z"})

    assert response.status_code == 200
    readings = response.json()["data"]
    assert len(readings) == 7 * HALF_HOURS_PER_DAY
    assert readings[0]["from"] == "2026-03-01T00:00:00Z"
    assert readings[-1]["to"] == "2026-03-08T00:00:00Z"


def test_a_different_window_gives_different_readings(authorised):
    """A fixed fixture would answer both of these identically."""
    headers, _ = authorised
    march = get(headers, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-02T00:00:00Z"})
    july = get(headers, **{"from": "2026-07-01T00:00:00Z", "to": "2026-07-02T00:00:00Z"})

    assert [r["energy"]["value"] for r in march.json()["data"]] != [
        r["energy"]["value"] for r in july.json()["data"]
    ]


def test_a_year_can_be_requested(authorised):
    """The previous 12 complete months, which is what a CAP asks for."""
    headers, _ = authorised
    response = get(
        headers, **{"from": "2025-03-01T00:00:00Z", "to": "2026-03-01T00:00:00Z"}
    )

    assert response.status_code == 200
    assert len(response.json()["data"]) == 365 * HALF_HOURS_PER_DAY


def test_readings_are_contiguous_half_hours(authorised):
    headers, _ = authorised
    readings = get(
        headers, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-03T00:00:00Z"}
    ).json()["data"]

    for earlier, later in zip(readings, readings[1:]):
        assert earlier["to"] == later["from"]


def test_to_defaults_to_now(authorised):
    """The registry API declares `to` optional, meaning up to the present."""
    headers, _ = authorised
    yesterday = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    response = get(headers, **{"from": yesterday.strftime("%Y-%m-%dT%H:%M:%SZ")})

    assert response.status_code == 200
    assert len(response.json()["data"]) == pytest.approx(HALF_HOURS_PER_DAY, abs=2)


def test_provenance_records_the_window_actually_served(authorised):
    """
    The metering period in the signed record has to describe the readings that
    accompany it. It previously named a window the data did not cover.
    """
    headers, records = authorised
    get(headers, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-08T00:00:00Z"})

    kwargs = records.call_args.kwargs
    assert kwargs["from_date"] == datetime.datetime(
        2026, 3, 1, tzinfo=datetime.timezone.utc
    )
    assert kwargs["to_date"] == datetime.datetime(
        2026, 3, 8, tzinfo=datetime.timezone.utc
    )


# ---------------------------------------------------------------------------
# Bad windows
# ---------------------------------------------------------------------------


def test_to_before_from_is_rejected(authorised):
    headers, _ = authorised
    response = get(
        headers, **{"from": "2026-03-08T00:00:00Z", "to": "2026-03-01T00:00:00Z"}
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_an_over_long_window_is_rejected(authorised):
    """Past the cap the response cannot be carried back from the Lambda."""
    headers, _ = authorised
    response = get(
        headers, **{"from": "2020-01-01T00:00:00Z", "to": "2026-01-01T00:00:00Z"}
    )

    assert response.status_code == 400
    assert "days" in response.json()["error_description"]


def test_a_long_window_needs_compression(authorised):
    """
    A client that will not take a compressed response is told so, rather than the
    load balancer failing on a response too large to return.
    """
    headers, _ = authorised
    long_enough = (UNCOMPRESSED_WINDOW + datetime.timedelta(days=1)).days
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    end = start + datetime.timedelta(days=long_enough)

    response = client.get(
        f"/datasources/{DEMO_METER_ID}/import"
        f"?from={start:%Y-%m-%dT%H:%M:%SZ}&to={end:%Y-%m-%dT%H:%M:%SZ}",
        headers={**headers, "Accept-Encoding": "identity"},
    )

    assert response.status_code == 400
    assert "gzip" in response.json()["error_description"]


# ---------------------------------------------------------------------------
# Size
# ---------------------------------------------------------------------------


def test_a_year_is_compressed_within_the_lambda_response_limit(authorised):
    """
    An ALB will carry at most 1MB back from a Lambda. A year of readings is several
    times that uncompressed, so compression is what makes the window servable.
    """
    headers, _ = authorised
    response = client.get(
        f"/datasources/{DEMO_METER_ID}/import"
        "?from=2025-03-01T00:00:00Z&to=2026-03-01T00:00:00Z",
        headers={**headers, "Accept-Encoding": "gzip"},
    )

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"

    # The test client decompresses transparently, so response.content is the body a
    # caller sees and the header carries what actually went over the wire.
    uncompressed = len(response.content)
    compressed = int(response.headers["content-length"])
    assert uncompressed > 1_000_000  # the reason compression is needed at all
    assert compressed < 1_000_000
    # Mangum base64s the compressed body, and that expansion counts against the
    # limit too.
    assert compressed * 4 / 3 < 1_000_000


# ---------------------------------------------------------------------------
# Reading shape
# ---------------------------------------------------------------------------


def test_readings_conform_to_the_registry_schema(authorised):
    headers, _ = authorised
    readings = get(
        headers, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-02T00:00:00Z"}
    ).json()["data"]

    for reading in readings:
        # The registry enum is lower case; this used to be "Electricity".
        assert reading["type"] == "electricity"
        assert reading["energy"]["unitCode"] in {"KWH", "WHR", "MTQ"}
        assert reading["energy"]["value"] >= 0
        # "Timestamp when reading was retrieved. Must be after 'to'."
        assert reading["takenAt"] > reading["to"]


def test_cumulative_accumulates(authorised):
    headers, _ = authorised
    readings = get(
        headers, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-02T00:00:00Z"}
    ).json()["data"]

    running = 0.0
    for reading in readings:
        running += reading["energy"]["value"]
        assert reading["cumulative"]["value"] == pytest.approx(running, abs=0.01)


def test_export_is_zero(authorised):
    """This household had no generation. Reporting its consumption as export would
    tell a CAP it exported everything it used."""
    headers, _ = authorised
    readings = get(
        headers,
        measure="export",
        **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-02T00:00:00Z"},
    ).json()["data"]

    assert readings
    assert all(reading["energy"]["value"] == 0 for reading in readings)


def test_datasources_advertises_the_registry_type(authorised):
    headers, _ = authorised
    sources = client.get("/datasources", headers=headers).json()["data"]

    assert {source["type"] for source in sources} <= {"electricity", "gas"}


# ---------------------------------------------------------------------------
# Date shifting
# ---------------------------------------------------------------------------


def test_the_shift_keeps_winter_colder_than_summer():
    """
    What the shift is for. A CAP multiplies each half hour by grid intensity, so a
    year that had lost its seasonal shape would give an answer that looks nothing
    like the household's real emissions.
    """
    def daily_total(month):
        start = datetime.datetime(2026, month, 10, tzinfo=datetime.timezone.utc)
        readings = consumption.readings(
            start,
            start + datetime.timedelta(days=1),
            models.EnergyType.ELECTRICITY,
            models.Measure.IMPORT,
        )
        return sum(reading["energy"]["value"] for reading in readings)

    assert daily_total(2) > daily_total(7) * 2


def test_the_shift_keeps_the_time_of_day():
    """
    The fixture is a whole number of days, so a shifted reading comes from the same
    time of day. An evening peak that drifted would misprice against a time varying
    grid intensity.
    """
    start, values = consumption.load_fixture()
    when = datetime.datetime(2026, 4, 15, 18, 30, tzinfo=datetime.timezone.utc)
    index = consumption._fixture_index(when, start, len(values))

    assert (start + index * consumption.INTERVAL).time() == when.time()


def test_a_misaligned_request_snaps_to_the_half_hour(authorised):
    """
    Both edges snap back to a boundary. `from` is inclusive, so 09:47 yields the
    09:30 reading that contains it rather than losing it; `to` is exclusive, so
    11:12 stops at 11:00 rather than returning a half hour reaching past it.
    """
    headers, _ = authorised
    readings = get(
        headers, **{"from": "2026-03-01T09:47:00Z", "to": "2026-03-01T11:12:00Z"}
    ).json()["data"]

    assert readings[0]["from"] == "2026-03-01T09:30:00Z"
    assert readings[-1]["to"] == "2026-03-01T11:00:00Z"


# ---------------------------------------------------------------------------
# The fixture itself
# ---------------------------------------------------------------------------


def test_the_fixture_is_a_whole_number_of_days():
    _, values = consumption.load_fixture()

    assert len(values) % HALF_HOURS_PER_DAY == 0


def test_the_fixture_credits_its_source():
    """Low Carbon London is CC-BY, so attribution travels with the data."""
    with open(f"{conf.ROOT_DIR}/data/consumption_year.json") as handle:
        fixture = json.load(handle)

    assert "creativecommons.org" in fixture["source"]["licence"]
    assert fixture["source"]["attribution"]
