#!/usr/bin/env python3
"""
Build a year of half-hourly gas volumes for the demo premises, and write it as a
fixture the resource API can serve alongside the electricity readings.

The readings are SYNTHETIC. No public dataset carries half-hourly domestic gas
volumes: Low Carbon London is electricity only, and neither Faraday release models
gas. So this constructs a profile from published aggregates rather than sampling one,
and the fixture says so in its own metadata.

What it is built from:

  * Ofgem's medium Typical Domestic Consumption Value for gas, 9,500 kWh a year. The
    electricity meter it is paired with, LCL household MAC000009, draws about 3,000
    kWh a year against a medium electricity TDCV of 2,500, so a typical household is
    the right order of magnitude for its gas.
  * The real daily mean temperature at the premises' postcode district through the
    same year the electricity comes from, so the gas responds to the same winter the
    electricity saw. Space heating follows heating degree days, base 15.5C, the
    standard UK base for domestic heating demand.
  * The end use split DESNZ publishes for domestic natural gas: roughly three
    quarters space heating, a fifth hot water, the rest cooking. Boiler run times put
    the heat where an occupied home uses it: a morning warm-up, an evening period, and
    midday running only when it is genuinely cold.

Every constant below carries, in the comment above it, the source that justifies its
value. The fixture states the figures it was built from and names this script, so a
reader who starts from the data can get back to them.

What it deliberately is not: a household anyone metered. It is the right shape and
the right magnitude, which is what a carbon calculation needs to be worth running,
and it should never be presented as observed data.

Usage:

    python synthesise_gas_data.py                 # 2013, default output
    python synthesise_gas_data.py --year 2013 --annual-kwh 11500

Re-running is safe: the weather response is cached, and the output is rewritten from
scratch.
"""

from __future__ import annotations

import argparse
import datetime
import json
import statistics
import sys
import urllib.error
import urllib.request
from pathlib import Path

HALF_HOUR = datetime.timedelta(minutes=30)
SLOTS_PER_DAY = 48

# South Lambeth, the outcode the demo premises reports.
POSTCODE_OUTCODE = "SW8"
LATITUDE, LONGITUDE = 51.4780, -0.1300

WEATHER_URL = "https://archive-api.open-meteo.com/v1/archive"
WEATHER_ATTRIBUTION = (
    "Daily mean temperatures from Open-Meteo.com's historical reanalysis "
    "(ERA5, Copernicus Climate Change Service). Licensed CC-BY 4.0."
)
WEATHER_LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"

# Ofgem's medium Typical Domestic Consumption Value for gas: the regulator's estimate
# of what a typical household burns in a year, and the anchor the whole profile is
# scaled to. 9,500 kWh replaced 11,500 on 1 July 2026, a 2,000 kWh cut reflecting how
# much less gas UK homes now use. These readings are served as present-day
# consumption, so the figure in force is the one to scale to, even though the load
# shape underneath comes from an earlier year.
# https://www.ofgem.gov.uk/consultation/review-typical-domestic-consumption-values
# https://www.ofgem.gov.uk/sites/default/files/2026-05/Review%20of%20typical%20domestic%20consumption%20values%20decision.pdf
ANNUAL_KWH = 9500

# Metered gas is billed by volume, and the conversion to energy is fixed in law:
# kWh = m3 * calorific value * 1.02264 / 3.6. The 1.02264 corrects the volume for
# temperature and pressure. 39.5 MJ/m3 is a representative calorific value; a real
# bill carries the average of the gas actually delivered to that premises.
# https://www.gov.uk/guidance/gas-meter-readings-and-bill-calculation
# https://www.legislation.gov.uk/uksi/1996/439/contents/made
KWH_PER_CUBIC_METRE = 39.5 * 1.02264 / 3.6

# The base temperature below which a UK home is assumed to want heat. 15.5C is the
# long-standing UK convention, used by CIBSE and by DESNZ: above it the incidental
# gains from bodies, cooking and appliances cover the fabric losses of a typical
# building and the heating stays off.
# https://www.degreedays.net/base-temperature
# https://www.cibse.org/knowledge-research/knowledge-portal/technical-memorandum-41-degree-days-theory-and-application-2006-pdf/
HEATING_BASE_C = 15.5

# Where the year's gas goes, from DESNZ's Energy Consumption in the UK: Table U3
# splits domestic consumption by end use and fuel, and these are its natural gas
# columns for 2024, the most recent year. The split is stable over time — 2013, the
# year the load shape comes from, was 74.4 / 23.3 / 2.3 — so nothing here turns on
# which year is taken. Space heating dominating is what gives gas its far stronger
# seasonality than electricity, and most of what a carbon calculation will see.
# https://www.gov.uk/government/statistics/energy-consumption-in-the-uk-2025
SPACE_HEATING_SHARE = 0.749
HOT_WATER_SHARE = 0.220
COOKING_SHARE = 0.031

# The temperature hot water is delivered at, which sets how hard the boiler works
# against the incoming main. HSE's legionella guidance puts stored water at 60C and
# water reaching the outlets at 50C or above, so 55C sits between the two. Only the
# ratio of winter to summer hot water demand depends on this, and that ratio barely
# moves for a few degrees either way.
# https://www.hse.gov.uk/healthservices/legionella.htm
CYLINDER_TARGET_C = 55.0

# Below this a half hour is reported as zero: a boiler either fires or it does not,
# and a thousandth of a cubic metre is not a firing. A judgement rather than a
# published figure; it only affects how the quietest summer half hours round.
FIRING_FLOOR_M3 = 0.001


class SynthesisError(Exception):
    """The profile could not be built."""


def _slot(hour: int, minute: int = 0) -> int:
    """The index of a half hour within the day."""
    return hour * 2 + minute // 30


def _band(shape: list[float], start: int, end: int, level: float) -> None:
    """Set a run of half hours to a level, in place. `end` is exclusive."""
    for index in range(start, end):
        shape[index] = level


def _smoothed(shape: list[float], passes: int = 2) -> list[float]:
    """
    Round off the edges of a shape built from rectangular bands.

    Nothing about a boiler is rectangular: it modulates rather than switching between
    fixed rates, and the fabric of the house carries heat across the moment the
    thermostat is satisfied. Left as bands the profile steps between flat plateaus,
    which is both wrong and conspicuously machine-made. Two passes of a light kernel,
    wrapped around midnight because the day is a cycle.
    """
    for _ in range(passes):
        size = len(shape)
        shape = [
            0.25 * shape[(index - 1) % size]
            + 0.5 * shape[index]
            + 0.25 * shape[(index + 1) % size]
            for index in range(size)
        ]
    return shape


def _normalised(shape: list[float]) -> list[float]:
    """Smooth the bands, then scale so the shape spreads exactly one day's volume."""
    shape = _smoothed(shape)
    total = sum(shape)
    if not total:
        raise SynthesisError("A daily shape summed to zero")
    return [value / total for value in shape]


# ---------------------------------------------------------------------------
# Daily shapes
# ---------------------------------------------------------------------------


def heating_shape(weekend: bool, cold: bool) -> list[float]:
    """
    How a day's space heating is spread across its half hours.

    A boiler does not deliver heat evenly. It fires hard to bring the house up from
    its overnight setback, then throttles back to hold temperature, and the pattern
    repeats in the evening. On a cold day the midday setback is shallower and the
    boiler keeps running between the two periods; on a mild day it stays off.
    """
    shape = [0.0] * SLOTS_PER_DAY

    if weekend:
        # Later start, and the house is occupied through the day.
        _band(shape, _slot(7, 30), _slot(9, 30), 1.0)  # warm-up
        _band(shape, _slot(9, 30), _slot(16), 0.45)  # held all day
    else:
        _band(shape, _slot(6), _slot(7), 1.0)  # warm-up
        _band(shape, _slot(7), _slot(8, 30), 0.7)  # holding while people are up
        if cold:
            # Only in real cold does the boiler run through an empty house.
            _band(shape, _slot(8, 30), _slot(15, 30), 0.3)

    # Evening: reheat as people come home, then hold until the setback.
    _band(shape, _slot(15, 30), _slot(17), 1.0)
    _band(shape, _slot(17), _slot(21, 30), 0.75)
    _band(shape, _slot(21, 30), _slot(22, 30), 0.45)

    if cold:
        # Frost protection keeps the house off its floor overnight.
        _band(shape, _slot(23), SLOTS_PER_DAY, 0.12)
        _band(shape, 0, _slot(6), 0.12)

    return _normalised(shape)


def hot_water_shape(weekend: bool) -> list[float]:
    """
    Hot water draw-off: showers in the morning, washing up and baths in the evening.
    A stored cylinder would reheat on a timer, a combi fires on demand; both land in
    the same two windows.
    """
    shape = [0.0] * SLOTS_PER_DAY
    if weekend:
        _band(shape, _slot(8), _slot(11), 1.0)
    else:
        _band(shape, _slot(6, 30), _slot(8, 30), 1.0)
    _band(shape, _slot(11), _slot(17), 0.15)
    _band(shape, _slot(18), _slot(22), 0.8)
    return _normalised(shape)


def cooking_shape(weekend: bool) -> list[float]:
    """A hob and oven: a small breakfast, a larger evening meal, lunch at weekends."""
    shape = [0.0] * SLOTS_PER_DAY
    _band(shape, _slot(7, 30), _slot(8, 30), 0.3)
    if weekend:
        _band(shape, _slot(12), _slot(13, 30), 0.8)
    _band(shape, _slot(17, 30), _slot(19, 30), 1.0)
    _band(shape, _slot(19, 30), _slot(20, 30), 0.3)
    return _normalised(shape)


# ---------------------------------------------------------------------------
# Weather
# ---------------------------------------------------------------------------


def daily_temperatures(year: int, cache: Path) -> list[float]:
    """
    Daily mean temperature at the premises for every day of the year.

    Cached, so re-running the script does not depend on the service being up.
    """
    cache_file = cache / f"open-meteo-{POSTCODE_OUTCODE}-{year}.json"
    if cache_file.exists():
        payload = json.loads(cache_file.read_text())
    else:
        query = (
            f"?latitude={LATITUDE}&longitude={LONGITUDE}"
            f"&start_date={year}-01-01&end_date={year}-12-31"
            "&daily=temperature_2m_mean&timezone=UTC"
        )
        request = urllib.request.Request(
            WEATHER_URL + query, headers={"User-Agent": "perseus-demo-edp/1.0"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as error:
            raise SynthesisError(f"Could not fetch {year} temperatures: {error}")
        cache.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(payload))

    temperatures = payload.get("daily", {}).get("temperature_2m_mean") or []
    expected = (datetime.date(year + 1, 1, 1) - datetime.date(year, 1, 1)).days
    if len(temperatures) != expected:
        raise SynthesisError(
            f"Expected {expected} daily temperatures for {year}, got "
            f"{len(temperatures)}"
        )
    if any(value is None for value in temperatures):
        raise SynthesisError(f"The {year} temperature series has gaps")
    return [float(value) for value in temperatures]


def mains_temperature(air: float) -> float:
    """
    Incoming mains water temperature, approximated from air temperature.

    Buried pipe damps and lags the air above it, so the main sits well above winter
    air and below summer air. The exact curve matters less than the direction: the
    cylinder has more work to do in January than in July. SAP, the government's
    methodology for assessing a dwelling's energy use, does this properly with a
    monthly cold water feed temperature table.

    https://www.gov.uk/guidance/standard-assessment-procedure
    """
    return 0.55 * air + 4.5


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_year(year: int, annual_kwh: float, temperatures: list[float]):
    """
    Return (half-hourly cubic metres, statistics) for the whole calendar year.

    Each component is allocated its share of the year, distributed across days by its
    own driver, then across each day by its own shape. Doing it in that order is what
    keeps the annual total exact while letting the daily totals move with the weather.
    """
    days = len(temperatures)
    first = datetime.date(year, 1, 1)

    degree_days = [max(0.0, HEATING_BASE_C - value) for value in temperatures]
    if not sum(degree_days):
        raise SynthesisError(f"{year} had no heating degree days at this location")

    # Hot water rises as the incoming main cools.
    water_load = [
        CYLINDER_TARGET_C - mains_temperature(value) for value in temperatures
    ]

    annual_m3 = annual_kwh / KWH_PER_CUBIC_METRE
    heating_m3 = annual_m3 * SPACE_HEATING_SHARE
    water_m3 = annual_m3 * HOT_WATER_SHARE
    cooking_m3 = annual_m3 * COOKING_SHARE

    # A day counts as cold once it is asking for a third of the year's worst day.
    cold_threshold = max(degree_days) / 3
    total_degree_days = sum(degree_days)
    total_water_load = sum(water_load)

    readings: list[float] = []
    daily_totals: list[float] = []

    for index in range(days):
        date = first + datetime.timedelta(days=index)
        weekend = date.weekday() >= 5
        cold = degree_days[index] >= cold_threshold

        heating_today = heating_m3 * degree_days[index] / total_degree_days
        water_today = water_m3 * water_load[index] / total_water_load
        cooking_today = cooking_m3 / days
        if weekend:
            cooking_today *= 1.3

        heat = heating_shape(weekend, cold)
        water = hot_water_shape(weekend)
        cook = cooking_shape(weekend)

        day = [
            heating_today * heat[slot]
            + water_today * water[slot]
            + cooking_today * cook[slot]
            for slot in range(SLOTS_PER_DAY)
        ]
        day = [round(value, 3) if value >= FIRING_FLOOR_M3 else 0.0 for value in day]
        readings.extend(day)
        daily_totals.append(sum(day))

    def mean_daily(months: tuple[int, ...]) -> float:
        wanted = [
            total
            for offset, total in enumerate(daily_totals)
            if (first + datetime.timedelta(days=offset)).month in months
        ]
        return statistics.fmean(wanted)

    summer = mean_daily((6, 7, 8))
    total_m3 = sum(readings)
    statistics_block = {
        "readings": len(readings),
        "annualCubicMetres": round(total_m3, 1),
        "annualKwhEquivalent": round(total_m3 * KWH_PER_CUBIC_METRE, 1),
        "meanDailyCubicMetres": round(total_m3 / days, 3),
        "winterSummerRatio": round(mean_daily((12, 1, 2)) / summer, 2) if summer else 0,
        "coldestDayCubicMetres": round(max(daily_totals), 3),
        "warmestDayCubicMetres": round(min(daily_totals), 3),
        "heatingDegreeDays": round(sum(degree_days), 1),
    }
    return readings, statistics_block


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--year", type=int, default=2013, help="Calendar year to build")
    parser.add_argument(
        "--annual-kwh",
        type=float,
        default=ANNUAL_KWH,
        help=f"Annual gas energy in kWh (default: {ANNUAL_KWH}, Ofgem medium TDCV)",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parents[1] / "data" / "gas_year.json"),
        help="Where to write the fixture",
    )
    parser.add_argument(
        "--cache",
        default=str(Path(__file__).resolve().parents[1] / "data" / ".lcl-cache"),
        help="Directory for the cached weather response",
    )
    args = parser.parse_args()

    try:
        temperatures = daily_temperatures(args.year, Path(args.cache))
        readings, stats = build_year(args.year, args.annual_kwh, temperatures)
    except SynthesisError as error:
        print(f"\nerror: {error}", file=sys.stderr)
        return 1

    fixture = {
        "_comment": (
            "SYNTHETIC. Generated by resource/scripts/synthesise_gas_data.py. Not "
            "metered data: no public dataset carries half-hourly domestic gas "
            "volumes, so this is constructed from published aggregates and real "
            "weather. Do not present it as an observed household."
        ),
        "synthetic": True,
        # Every figure the profile rests on, with where it came from, so a reader can
        # check the construction without opening the script.
        # The figures the profile rests on. Each one is sourced in the script named
        # above, beside the constant it sets.
        "method": {
            "annualEnergyBasis": "Ofgem medium gas Typical Domestic Consumption Value",
            "annualKwh": args.annual_kwh,
            "kwhPerCubicMetre": round(KWH_PER_CUBIC_METRE, 4),
            "heatingBaseTemperatureC": HEATING_BASE_C,
            "shares": {
                "spaceHeating": SPACE_HEATING_SHARE,
                "hotWater": HOT_WATER_SHARE,
                "cooking": COOKING_SHARE,
                "source": (
                    "DESNZ Energy Consumption in the UK, Table U3, "
                    "natural gas columns, 2024"
                ),
            },
            "hotWaterDeliveryTemperatureC": CYLINDER_TARGET_C,
            "pairedWith": (
                "The electricity fixture's household, chosen because it is gas heated "
                "and so leaves room for a boiler"
            ),
        },
        "weather": {
            "name": "Open-Meteo historical reanalysis",
            "url": WEATHER_URL,
            "licence": WEATHER_LICENCE_URL,
            "attribution": WEATHER_ATTRIBUTION,
            "location": {"ukPostcodeOutcode": POSTCODE_OUTCODE},
        },
        "year": args.year,
        "start": f"{args.year}-01-01T00:00:00Z",
        "intervalMinutes": 30,
        "unitCode": "MTQ",
        "timestampConvention": "periodStart",
        "statistics": stats,
        "readings": readings,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, separators=(",", ":")), encoding="utf-8")

    print(
        f"Wrote {output} — {stats['readings']} readings, "
        f"{stats['annualCubicMetres']} m3 "
        f"({stats['annualKwhEquivalent']} kWh) over {args.year}, "
        f"winter/summer {stats['winterSummerRatio']}, "
        f"{output.stat().st_size / 1024:.0f}KB",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
