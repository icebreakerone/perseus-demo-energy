"""
Meter readings for a requested window.

The demo serves one premises with two meters. Electricity is a real household's year
of half-hourly readings from the UK Power Networks Low Carbon London trial, extracted
by `scripts/extract_lcl_data.py`. Gas has no equivalent source — nobody publishes
half-hourly domestic gas volumes — so `data/gas_profile.json` carries the monthly
demand DESNZ does publish, and `_expand_profile` spreads it across the year.

The household was chosen for being gas heated: its electricity is appliances and
lighting, lifting mildly in winter with the lights, which leaves room for a boiler
alongside it. An electrically heated meter would have the more dramatic electricity
curve, but pairing one with a gas profile would heat the same house twice and hand a
CAP a premises that cannot exist.

Because each fixture is a single year and callers ask for windows in the present,
readings are date-shifted onto the requested window (see `_fixture_index`). Swap
`load_fixture` for a different source — generated profiles, a real meter feed — and
nothing above this module changes.
"""

from __future__ import annotations

import calendar
import datetime
import functools
import json
from typing import Iterator, NamedTuple

from . import conf
from . import models

# The fixtures are rings of consecutive half hours. Nothing here assumes which year
# they came from, only that they are a whole number of days long.
INTERVAL = datetime.timedelta(minutes=30)
INTERVALS_PER_DAY = 24 * 60 // 30

# A year of half-hourly readings is 17,520 entries and around 3.5MB of JSON. The
# response is gzipped, but a cap keeps a careless request from blowing the 1MB an
# ALB will carry back from a Lambda. Thirteen months covers "the previous 12
# complete months", which is what a CAP actually asks for.
MAX_WINDOW = datetime.timedelta(days=396)


class Source(NamedTuple):
    """Where one energy type's readings live, and what the API reports them in."""

    filename: str
    unit: models.UnitCode
    # Fixtures are stored in the unit their source published: kWh for the metered
    # electricity, cubic metres for the gas. The API reports watt hours and cubic
    # metres, so only electricity is scaled.
    scale: float


SOURCES: dict[models.EnergyType, Source] = {
    models.EnergyType.ELECTRICITY: Source(
        "consumption_year.json", models.UnitCode.WHR, 1000.0
    ),
    models.EnergyType.GAS: Source("gas_profile.json", models.UnitCode.MTQ, 1.0),
}


class FixtureError(Exception):
    """A fixture is missing or unusable."""


def _expand_profile(fixture: dict, start: datetime.datetime) -> tuple[float, ...]:
    """
    A year of half hours from twelve monthly shares and one day's shape.

    There is no metered half-hourly source for domestic gas to draw on, so rather than
    model a boiler this states what is published: the share of a year's domestic gas
    demand falling in each month. Within a day the shape is fixed and illustrative,
    which costs nothing — gas carries a constant emissions factor, so the shape within
    a day cannot change a carbon calculation, only whether a plot looks plausible.

    The year in `start` supplies the month lengths. It is a non-leap year, matching the
    electricity fixture, which is what keeps the two meters in phase.
    """
    annual = float(fixture["annualCubicMetres"])
    shares = fixture["monthlyShares"]
    shape = [float(weight) for weight in fixture["dailyShape"]]
    if len(shape) != INTERVALS_PER_DAY:
        raise FixtureError(
            f"A daily shape needs {INTERVALS_PER_DAY} weights, one per half hour, "
            f"and this one has {len(shape)}"
        )

    values: list[float] = []
    for month in range(1, 13):
        days = calendar.monthrange(start.year, month)[1]
        daily = annual * float(shares[str(month)]) / days
        for _ in range(days):
            values.extend(round(daily * weight, 4) for weight in shape)
    return tuple(values)


@functools.lru_cache(maxsize=len(models.EnergyType))
def load_fixture(
    energy_type: models.EnergyType = models.EnergyType.ELECTRICITY,
) -> tuple[datetime.datetime, tuple[float, ...]]:
    """
    Read one energy type's fixture, returning the instant it starts and its readings
    in the unit it was stored in. Cached: the Lambda holds them between invocations.
    """
    path = f"{conf.ROOT_DIR}/data/{SOURCES[energy_type].filename}"
    try:
        with open(path) as handle:
            fixture = json.load(handle)
    except FileNotFoundError:
        raise FixtureError(f"No {energy_type.value} fixture at {path}")

    start = datetime.datetime.fromisoformat(
        fixture["start"].replace("Z", "+00:00")
    ).astimezone(datetime.timezone.utc)

    # Metered readings are stored one by one; a profile is expanded into them here.
    readings = fixture.get("readings")
    values = (
        tuple(float(value) for value in readings)
        if readings
        else _expand_profile(fixture, start)
    )

    if not values:
        raise FixtureError(f"Fixture at {path} has no readings")
    if len(values) % INTERVALS_PER_DAY:
        raise FixtureError(
            f"Fixture at {path} holds {len(values)} readings, which is not a whole "
            "number of days, so shifting it would move the time of day"
        )
    return start, values


def _fixture_index(when: datetime.datetime, start: datetime.datetime, size: int) -> int:
    """
    Map a requested half hour onto a reading in a fixture.

    A plain modulo over the ring. Because a fixture is a whole number of days, time of
    day is preserved exactly: 09:30 on the requested day reads the fixture's 09:30.
    Because it is very nearly a whole year, so is the position in the year, drifting
    only by the odd leap day. That is what keeps a January request cold and a July
    request warm, which is the whole point of using a year of real weather.

    Both fixtures cover the same year at the same resolution, so both shift by the
    same offset and the premises stays internally consistent: the day the gas works
    hardest is the day the electricity saw that same January.

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
    source = SOURCES[energy_type]
    start, values = load_fixture(energy_type)

    exporting = measure is models.Measure.EXPORT
    result: list[dict] = []
    cumulative = 0.0

    for period_start, period_end in _windows(from_date, to_date):
        if exporting:
            value = 0.0
        else:
            index = _fixture_index(period_start, start, len(values))
            value = values[index] * source.scale

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
                "energy": {"value": value, "unitCode": source.unit.value},
                "cumulative": {"value": cumulative, "unitCode": source.unit.value},
            }
        )

    return result
