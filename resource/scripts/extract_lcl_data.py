#!/usr/bin/env python3
"""
Extract one household's year of half-hourly readings from the Low Carbon London
dataset, and write it as a fixture the resource API can serve.

    https://data.london.gov.uk/dataset/smartmeter-energy-consumption-data-in-london-households-vqm0d

Low Carbon London is real metered data: 5,567 London households, half-hourly kWh,
November 2011 to February 2014, collected by UK Power Networks. Licensed CC-BY 4.0,
so the extracted readings can be redistributed with attribution.

The default household, MAC000009, is gas heated: its electricity is appliances and
lighting on a flat baseload, lifting mildly in winter with the lights. That is the
point of choosing it. The demo pairs this meter with a synthesised gas profile, and a
home cannot be heated twice.

MAC000003, the meter the original 100-reading fixture came from, is Economy 7 electric
storage heating: a 2.5x winter swing, but 69% of its year drawn between midnight and
07:00 and no room for a gas boiler beside it. --survey tells the two apart.

Only the members of the archive that are actually needed get downloaded. The archive
is 795MB but supports HTTP range requests, and each of its 168 members is about 4.7MB
compressed, so finding a household in the first member costs 4.7MB rather than 795MB.

Usage:

    python extract_lcl_data.py                        # MAC000009, 2013, default output
    python extract_lcl_data.py --household MAC000003 --year 2013
    python extract_lcl_data.py --survey               # report candidate households

Re-running is safe: downloaded members are cached, and the output file is rewritten
from scratch.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import io
import json
import statistics
import struct
import sys
import urllib.request
import zlib
from collections import defaultdict
from pathlib import Path

# The partitioned release: same 167M rows as the single-file download, split into
# 168 members. Splitting is what makes a targeted range fetch cheap.
ARCHIVE_URL = (
    "https://data.london.gov.uk/download/vqm0d/"
    "04feba67-f1a3-4563-98d0-f3071e3d56d1/Partitioned%20LCL%20Data.zip"
)
ATTRIBUTION = (
    "SmartMeter Energy Consumption Data in London Households, UK Power Networks "
    "Low Carbon London project, via the London Datastore. Licensed CC-BY 4.0."
)
SOURCE_URL = (
    "https://data.london.gov.uk/dataset/"
    "smartmeter-energy-consumption-data-in-london-households-vqm0d"
)
LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"

# The datastore refuses urllib's default agent with a 403.
USER_AGENT = "perseus-demo-edp/1.0 (+https://github.com/icebreakerone)"

HALF_HOUR = datetime.timedelta(minutes=30)
SLOTS_PER_DAY = 48


class ExtractError(Exception):
    """Anything that stops us producing a fixture."""


# ---------------------------------------------------------------------------
# Reading the archive over HTTP, a member at a time
# ---------------------------------------------------------------------------


def fetch_range(url: str, start: int, end: int, attempts: int = 5) -> bytes:
    """
    Fetch bytes [start, end] inclusive. The London Datastore intermittently answers
    a range request with a 504, so retry rather than fail the whole extraction.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            headers={"Range": f"bytes={start}-{end}", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                if response.status != 206:
                    raise ExtractError(
                        f"Server ignored the range request, status {response.status}. "
                        "The whole 795MB archive would be downloaded instead."
                    )
                return response.read()
        except ExtractError:
            raise
        except Exception as error:  # transient network or gateway failure
            last_error = error
            print(
                f"  range request failed ({error}), retrying "
                f"{attempt + 1}/{attempts - 1}",
                file=sys.stderr,
            )
    raise ExtractError(f"Could not fetch bytes {start}-{end}: {last_error}")


def archive_size(url: str) -> int:
    """
    Total archive length, taken from the Content-Range of a one-byte request. HEAD is
    answered with a 403 here, and a range GET has to work anyway for the rest of this
    to be viable, so this doubles as an early check that it does.
    """
    request = urllib.request.Request(
        url, headers={"Range": "bytes=0-0", "User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        content_range = response.headers.get("Content-Range", "")
    if "/" not in content_range:
        raise ExtractError(
            "Archive does not support range requests, so the whole 795MB would have "
            "to be downloaded. Fetch it by hand and re-run against a local copy."
        )
    return int(content_range.rsplit("/", 1)[1])


def _zip64_values(extra: bytes) -> list[int]:
    """Pull the 8-byte values out of a Zip64 extended information extra field."""
    offset = 0
    while offset < len(extra) - 3:
        header_id, size = struct.unpack("<HH", extra[offset : offset + 4])
        if header_id == 1:
            count = size // 8
            return list(
                struct.unpack(
                    "<" + "Q" * count, extra[offset + 4 : offset + 4 + count * 8]
                )
            )
        offset += 4 + size
    return []


def list_members(url: str, size: int) -> list[tuple[str, int, int]]:
    """
    Read the archive's central directory and return (name, local_header_offset,
    compressed_size) for each member, without downloading the members themselves.
    """
    tail = fetch_range(url, max(0, size - 65536), size - 1)

    end_record = tail.rfind(b"PK\x05\x06")
    if end_record < 0:
        raise ExtractError("No end-of-central-directory record; not a zip archive?")
    _, _, _, _, _, directory_size, directory_offset, _ = struct.unpack(
        "<IHHHHIIH", tail[end_record : end_record + 22]
    )

    # A directory beyond 4GB is recorded in the Zip64 record instead.
    if directory_offset == 0xFFFFFFFF or directory_size == 0xFFFFFFFF:
        zip64 = tail.rfind(b"PK\x06\x06")
        if zip64 < 0:
            raise ExtractError("Zip64 offsets expected but no Zip64 record found")
        fields = struct.unpack("<IQHHIIQQQQ", tail[zip64 : zip64 + 56])
        directory_size, directory_offset = fields[9], fields[8]

    directory = fetch_range(
        url, directory_offset, directory_offset + directory_size - 1
    )

    members: list[tuple[str, int, int]] = []
    offset = 0
    while (
        offset < len(directory) - 4 and directory[offset : offset + 4] == b"PK\x01\x02"
    ):
        header = struct.unpack("<IHHHHHHIIIHHHHHII", directory[offset : offset + 46])
        method = header[4]
        compressed_size, uncompressed_size = header[8], header[9]
        name_length, extra_length, comment_length = header[10], header[11], header[12]
        local_offset = header[16]

        name = directory[offset + 46 : offset + 46 + name_length].decode(
            "utf-8", "replace"
        )
        extra = directory[
            offset + 46 + name_length : offset + 46 + name_length + extra_length
        ]

        if method not in (0, 8):
            raise ExtractError(f"{name} uses unsupported compression method {method}")

        # Zip64 substitutes values in a fixed order for whichever fields are maxed out.
        values = _zip64_values(extra)
        consumed = 0
        if uncompressed_size == 0xFFFFFFFF and values:
            consumed += 1
        if compressed_size == 0xFFFFFFFF and len(values) > consumed:
            compressed_size = values[consumed]
            consumed += 1
        if local_offset == 0xFFFFFFFF and len(values) > consumed:
            local_offset = values[consumed]

        if not name.endswith("/"):
            members.append((name, local_offset, compressed_size))

        offset += 46 + name_length + extra_length + comment_length

    if not members:
        raise ExtractError("Central directory listed no files")
    return sorted(members)


def read_member(url: str, offset: int, compressed_size: int, cache: Path) -> str:
    """
    Fetch one member and inflate it. Cached on disk so re-runs cost nothing.

    The local file header sits immediately before the data and repeats the name and
    extra field lengths, which is what tells us where the compressed bytes begin.
    """
    if cache.exists():
        return cache.read_text(encoding="utf-8", errors="replace")

    # 30 header bytes plus name and extra, then the payload. A 4KB pad covers the
    # header comfortably; the extra field is a few dozen bytes at most.
    raw = fetch_range(url, offset, offset + compressed_size + 4096)
    if raw[:4] != b"PK\x03\x04":
        raise ExtractError("Expected a local file header; the archive may have moved")
    name_length, extra_length = struct.unpack("<HH", raw[26:30])
    start = 30 + name_length + extra_length

    text = zlib.decompressobj(-15).decompress(raw[start:]).decode("utf-8", "replace")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(text, encoding="utf-8")
    return text


# ---------------------------------------------------------------------------
# Turning CSV rows into a clean year
# ---------------------------------------------------------------------------


def parse_rows(text: str):
    """
    Yield (household, timestamp, kwh) from one member's CSV.

    Columns are LCLid, stdorToU, DateTime, "KWH/hh (per half hour) ". Header and
    values both carry stray whitespace, and some readings are the literal "Null".
    """
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return
    fields = {name.strip(): name for name in reader.fieldnames}
    id_field = fields.get("LCLid")
    time_field = fields.get("DateTime")
    kwh_field = next((raw for name, raw in fields.items() if "KWH" in name), None)
    if not (id_field and time_field and kwh_field):
        raise ExtractError(f"Unexpected columns: {reader.fieldnames}")

    for row in reader:
        raw_value = (row.get(kwh_field) or "").strip()
        if not raw_value or raw_value.lower() in ("null", "nan"):
            continue
        try:
            kwh = float(raw_value)
        except ValueError:
            continue
        stamp = (row.get(time_field) or "").strip()[:19]
        try:
            when = datetime.datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        yield (row[id_field].strip(), when, kwh)


def build_year(
    readings: dict[datetime.datetime, list[float]], year: int
) -> tuple[list[float], dict]:
    """
    Turn the collected readings into exactly one year of half-hourly values.

    Real data needs three repairs. Duplicate timestamps appear a dozen or so times a
    year and are averaged. A handful of slots are missing and are filled by linear
    interpolation between their neighbours. Anything still missing at the very start
    or end is carried inward from the nearest reading.
    """
    start = datetime.datetime(year, 1, 1)
    end = datetime.datetime(year + 1, 1, 1)
    expected = int((end - start) / HALF_HOUR)

    duplicates = sum(1 for values in readings.values() if len(values) > 1)
    averaged = {when: statistics.fmean(values) for when, values in readings.items()}

    slots: list[float | None] = []
    for index in range(expected):
        slots.append(averaged.get(start + index * HALF_HOUR))

    missing = [index for index, value in enumerate(slots) if value is None]
    known = [index for index, value in enumerate(slots) if value is not None]
    if not known:
        raise ExtractError(f"No readings at all for {year}")

    for index in missing:
        before = next((i for i in reversed(known) if i < index), None)
        after = next((i for i in known if i > index), None)
        if before is None:
            slots[index] = slots[after]  # type: ignore[index]
        elif after is None:
            slots[index] = slots[before]  # type: ignore[index]
        else:
            span = after - before
            weight = (index - before) / span
            low, high = slots[before], slots[after]
            slots[index] = low + (high - low) * weight  # type: ignore[operator]

    values = [round(float(value), 4) for value in slots]  # type: ignore[arg-type]
    return values, {
        "expectedReadings": expected,
        "duplicateTimestampsAveraged": duplicates,
        "missingReadingsInterpolated": len(missing),
    }


def seasonality(values: list[float], year: int) -> float:
    """
    Ratio of mean winter daily consumption to mean summer daily consumption. A gas
    heated home sits around 1.2 to 1.6, the lift coming from lighting rather than
    heat. Much above 2.0 means the heating itself is electric.
    """
    start = datetime.datetime(year, 1, 1)
    months: dict[int, list[float]] = defaultdict(list)
    for index, value in enumerate(values):
        months[(start + index * HALF_HOUR).month].append(value)

    def mean_daily(wanted: tuple[int, ...]) -> float:
        totals = [
            statistics.fmean(months[m]) * SLOTS_PER_DAY for m in wanted if months[m]
        ]
        return statistics.fmean(totals) if totals else 0.0

    summer = mean_daily((6, 7, 8))
    return mean_daily((12, 1, 2)) / summer if summer else 0.0


def _electrically_heated(ratio: float, night: float) -> bool:
    """Both marks together: the storage heaters and the window they charge in."""
    return ratio > 2.0 and night > 0.6


def overnight_share(values: list[float], year: int) -> float:
    """
    Fraction of the year's energy drawn between midnight and 07:00.

    Economy 7 storage heaters charge in exactly that window and stop dead at 07:00, so
    a share above about 0.6 marks an electrically heated home. Those are the households
    to avoid here: their winter shape is real, but pairing one with a synthesised gas
    profile would heat the same house twice.
    """
    total = sum(values)
    if not total:
        return 0.0
    start = datetime.datetime(year, 1, 1)
    night = sum(
        value
        for index, value in enumerate(values)
        if (start + index * HALF_HOUR).hour < 7
    )
    return night / total


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def scan(url: str, size: int, cache: Path, limit: int, wanted: str | None, year: int):
    """
    Walk members until the wanted household's year is complete, or until `limit`
    members have been read when surveying.
    """
    members = list_members(url, size)
    print(f"Archive holds {len(members)} members", file=sys.stderr)

    collected: dict[str, dict[datetime.datetime, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    year_start = datetime.datetime(year, 1, 1)
    year_end = datetime.datetime(year + 1, 1, 1)

    for number, (name, offset, compressed) in enumerate(members[:limit], start=1):
        cache_file = cache / f"{Path(name).stem}.csv"
        print(
            f"[{number}/{min(limit, len(members))}] {name}"
            f"{' (cached)' if cache_file.exists() else f' ({compressed / 1e6:.1f}MB)'}",
            file=sys.stderr,
        )
        text = read_member(url, offset, compressed, cache_file)

        for household, when, kwh in parse_rows(text):
            if wanted and household != wanted:
                continue
            if year_start <= when < year_end:
                collected[household][when].append(kwh)

        if wanted and collected.get(wanted):
            found = len(collected[wanted])
            expected = int((year_end - year_start) / HALF_HOUR)
            # Households are grouped, so once a member yields a full year there is
            # nothing further to find.
            if found >= expected - SLOTS_PER_DAY:
                print(f"  {wanted}: {found} readings, complete", file=sys.stderr)
                break
            print(f"  {wanted}: {found} readings so far", file=sys.stderr)

    return collected


def command_survey(args) -> int:
    size = archive_size(args.url)
    collected = scan(
        args.url, size, Path(args.cache), args.max_members, None, args.year
    )
    if not collected:
        print(f"No households had readings in {args.year}", file=sys.stderr)
        return 1

    expected = int(
        (datetime.datetime(args.year + 1, 1, 1) - datetime.datetime(args.year, 1, 1))
        / HALF_HOUR
    )
    rows = []
    for household, readings in collected.items():
        if len(readings) < expected * 0.99:
            continue
        values, _ = build_year(readings, args.year)
        rows.append(
            (
                household,
                sum(values),
                sum(values) / 365,
                seasonality(values, args.year),
                overnight_share(values, args.year),
            )
        )

    # Electric heating last, so the households that can carry a gas profile read first.
    rows.sort(key=lambda row: (_electrically_heated(row[3], row[4]), row[0]))
    print(f"\n{len(rows)} households with a complete {args.year}\n")
    print(
        f"{'household':12s} {'annual kWh':>11s} {'mean daily':>11s} "
        f"{'winter/summer':>14s} {'overnight':>10s}  heating"
    )
    for household, annual, daily, ratio, night in rows:
        heating = (
            "electric (E7)" if _electrically_heated(ratio, night) else "not electric"
        )
        print(
            f"{household:12s} {annual:11.1f} {daily:11.2f} {ratio:14.2f} "
            f"{night:9.1%}  {heating}"
        )
    print(
        "\nOvernight is midnight to 07:00. A household drawing most of its year in that "
        "window, with a winter/summer ratio well above 2, runs Economy 7 storage "
        "heaters. Pair gas with a 'not electric' household instead.\n"
    )
    return 0


def command_extract(args) -> int:
    size = archive_size(args.url)
    collected = scan(
        args.url, size, Path(args.cache), args.max_members, args.household, args.year
    )

    readings = collected.get(args.household)
    if not readings:
        raise ExtractError(
            f"{args.household} had no readings in {args.year}. It may live in a later "
            f"member: raise --max-members (currently {args.max_members}), or run "
            f"--survey to see which households are available."
        )

    values, repairs = build_year(readings, args.year)
    if repairs["missingReadingsInterpolated"] > len(values) * 0.02:
        raise ExtractError(
            f"{args.household} is missing "
            f"{repairs['missingReadingsInterpolated']} of {len(values)} readings in "
            f"{args.year}, too many to interpolate over. Choose another household or "
            "year with --survey."
        )

    ratio = seasonality(values, args.year)
    fixture = {
        "_comment": (
            "Generated by resource/scripts/extract_lcl_data.py. Real metered readings, "
            "date-shifted at request time onto the window the caller asks for."
        ),
        "source": {
            "name": "UK Power Networks Low Carbon London",
            "url": SOURCE_URL,
            "licence": LICENCE_URL,
            "attribution": ATTRIBUTION,
        },
        "household": args.household,
        "year": args.year,
        # Readings are consecutive half hours from this instant, so only the first
        # timestamp is stored; the loader derives the rest.
        "start": f"{args.year}-01-01T00:00:00Z",
        "intervalMinutes": 30,
        "unitCode": "KWH",
        # LCL timestamps the start of each half hour, which is the convention the
        # original fixture used and the one the API's from/to describe.
        "timestampConvention": "periodStart",
        "statistics": {
            "readings": len(values),
            "annualKwh": round(sum(values), 1),
            "meanDailyKwh": round(sum(values) / 365, 2),
            "winterSummerRatio": round(ratio, 2),
            **repairs,
        },
        "readings": values,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, separators=(",", ":")), encoding="utf-8")

    print(
        f"\nWrote {output} — {len(values)} readings, "
        f"{sum(values):.0f} kWh over {args.year}, "
        f"winter/summer {ratio:.2f}, {output.stat().st_size / 1024:.0f}KB",
        file=sys.stderr,
    )
    if repairs["missingReadingsInterpolated"] or repairs["duplicateTimestampsAveraged"]:
        print(
            f"Repaired {repairs['missingReadingsInterpolated']} missing and "
            f"{repairs['duplicateTimestampsAveraged']} duplicated readings",
            file=sys.stderr,
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--household",
        default="MAC000009",
        help="LCL household id (default: MAC000009, the demo's gas heated meter)",
    )
    parser.add_argument(
        "--year", type=int, default=2013, help="Calendar year to extract"
    )
    parser.add_argument(
        "--output",
        default=str(
            Path(__file__).resolve().parents[1] / "data" / "consumption_year.json"
        ),
        help="Where to write the fixture",
    )
    parser.add_argument("--url", default=ARCHIVE_URL, help="Override the archive URL")
    parser.add_argument(
        "--cache",
        default=str(Path(__file__).resolve().parents[1] / "data" / ".lcl-cache"),
        help="Directory for downloaded members, so re-runs are free",
    )
    parser.add_argument(
        "--max-members",
        type=int,
        default=8,
        help="How many archive members to read before giving up (each is ~4.7MB)",
    )
    parser.add_argument(
        "--survey",
        action="store_true",
        help="Report candidate households and their seasonality instead of extracting",
    )
    args = parser.parse_args()

    try:
        return command_survey(args) if args.survey else command_extract(args)
    except ExtractError as error:
        print(f"\nerror: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
