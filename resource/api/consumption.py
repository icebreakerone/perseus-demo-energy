"""
Meter readings for a requested window.

The demo serves one real household's year of half-hourly readings, taken from the
UK Power Networks Low Carbon London trial and extracted by
`scripts/extract_lcl_data.py`. A caller asking for last February gets that
household's February: real consumption, with the heating season in it.

Because the fixture is a single year and callers ask for windows in the present,
readings are date-shifted onto the requested window (see `_fixture_index`). Swap
`load_fixture` for a different source — generated profiles, a real meter feed —
and nothing above this module changes.
"""

from __future__ import annotations

import datetime
import functools
import json
from typing import Iterator

from . import conf
from . import models

# The fixture is a ring of consecutive half hours. Nothing here assumes which year
# it came from, only that it is a whole number of days long.
INTERVAL = datetime.timedelta(minutes=30)
INTERVALS_PER_DAY = 24 * 60 // 30

# A year of half-hourly readings is 17,520 entries and around 3.5MB of JSON. The
# response is gzipped, but a cap keeps a careless request from blowing the 1MB an
# ALB will carry back from a Lambda. Thirteen months covers "the previous 12
# complete months", which is what a CAP actually asks for.
MAX_WINDOW = datetime.timedelta(days=396)


class FixtureError(Exception):
    """The fixture is missing or unusable."""


@functools.lru_cache(maxsize=1)
def load_fixture() -> tuple[datetime.datetime, tuple[float, ...]]:
    """
    Read the consumption fixture, returning the instant it starts and its readings
    in kWh. Cached: the Lambda holds it between invocations.
    """
    path = f"{conf.ROOT_DIR}/data/consumption_year.json"
    try:
        with open(path) as handle:
            fixture = json.load(handle)
    except FileNotFoundError:
        raise FixtureError(
            f"No consumption fixture at {path}. Generate one with "
            "scripts/extract_lcl_data.py"
        )

    readings = fixture.get("readings")
    if not readings:
        raise FixtureError(f"Consumption fixture at {path} has no readings")
    if len(readings) % INTERVALS_PER_DAY:
        raise FixtureError(
            f"Consumption fixture at {path} holds {len(readings)} readings, which is "
            "not a whole number of days, so shifting it would move the time of day"
        )

    start = datetime.datetime.fromisoformat(
        fixture["start"].replace("Z", "+00:00")
    ).astimezone(datetime.timezone.utc)
    return start, tuple(float(value) for value in readings)


def _fixture_index(when: datetime.datetime, start: datetime.datetime, size: int) -> int:
    """
    Map a requested half hour onto a reading in the fixture.

    A plain modulo over the ring. Because the fixture is a whole number of days,
    time of day is preserved exactly: 09:30 on the requested day reads the fixture's
    09:30. Because it is very nearly a whole year, so is the position in the year,
    drifting only by the odd leap day. That is what keeps a January request cold and
    a July request warm, which is the whole point of using a year of real data.

    Day of the week is not preserved: 365 is not a multiple of 7, so weekday phase
    slips by a day per year. Seasonal shape drives a carbon calculation and weekday
    shape does not, so the trade goes this way round.
    """
    offset = int((when - start) / INTERVAL)
    return offset % size


def _windows(
    from_date: datetime.datetime, to_date: datetime.datetime
) -> Iterator[tuple[datetime.datetime, datetime.datetime]]:
    """
    Yield each half hour in [from_date, to_date), the interval boundaries the API's
    `from` inclusive / `to` exclusive describe.
    """
    edge = from_date
    while edge < to_date:
        yield edge, edge + INTERVAL
        edge += INTERVAL


def align(when: datetime.datetime) -> datetime.datetime:
    """
    Snap an instant back to the half hour containing it, so a caller passing
    09:47 gets the 09:30 reading rather than nothing.
    """
    return when.replace(minute=0 if when.minute < 30 else 30, second=0, microsecond=0)


def readings(
    from_date: datetime.datetime,
    to_date: datetime.datetime,
    energy_type: models.EnergyType,
    measure: models.Measure,
) -> list[dict]:
    """
    Build the readings covering [from_date, to_date) for one data source.

    Export is always zero. We do not have exports in our sample data set
    """
    start, values = load_fixture()

    if energy_type is models.EnergyType.GAS:
        source = gas_readings(from_date, to_date)
        unit = models.UnitCode.MTQ
    else:
        source = None
        unit = models.UnitCode.WHR

    exporting = measure is models.Measure.EXPORT
    result: list[dict] = []
    cumulative = 0.0

    for index, (period_start, period_end) in enumerate(_windows(from_date, to_date)):
        if exporting:
            value = 0.0
        elif source is not None:
            value = source[index]
        else:
            # Fixture is kWh; the API reports electricity in watt hours.
            value = values[_fixture_index(period_start, start, len(values))] * 1000

        value = round(value, 4)
        cumulative = round(cumulative + value, 4)
        result.append(
            {
                "type": energy_type.value,
                "from": period_start,
                "to": period_end,
                # A meter reports an interval once it has closed. The spec requires
                # takenAt to fall after `to`, so it lands one interval later.
                "takenAt": period_end + INTERVAL,
                "energy": {"value": value, "unitCode": unit.value},
                "cumulative": {"value": cumulative, "unitCode": unit.value},
            }
        )

    return result


def gas_readings(
    from_date: datetime.datetime, to_date: datetime.datetime
) -> list[float]:
    """
    Placeholder until the gas profile lands. Returns one value per half hour.
    """
    return [0.0 for _ in _windows(from_date, to_date)]
