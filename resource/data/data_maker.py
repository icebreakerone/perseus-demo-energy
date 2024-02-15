import datetime
import random
import json


class simple_utc(datetime.tzinfo):
    def tzname(self, **kwargs):
        return "UTC"

    def utcoffset(self, dt):
        return datetime.timedelta(0)


def create_data():
    """ "
    Returns a list of consumption objects with random values for consumption
    value between 50 and 300, and datestamps every 30 minutes between now and 7 days ago

    Use the following format:

    {
            "type": "Electricity",
            "from": "2023-10-18T00:00:00Z",
            "to": "2023-10-18T00:30:00Z",
            "consumption": {
                "value": 123.45,
                "unitCode": "WHR"
            }
        }
    """
    now = datetime.datetime.utcnow().replace(
        tzinfo=simple_utc(), minute=0, second=0, microsecond=0
    )
    earlier = now - datetime.timedelta(days=7)
    delta = datetime.timedelta(minutes=30)
    data = []
    while earlier < now:
        data.append(
            {
                "type": "Electricity",
                "from": earlier.isoformat(),
                "to": (earlier + delta).isoformat(),
                "consumption": {
                    "value": random.randint(500, 3000) / 10,
                    "unitCode": "WHR",
                },
            }
        )
        earlier += delta
    return data


if __name__ == "__main__":
    data = create_data()
    json_object = {"data": data}
    with open("data/7_day_consumption.json", "w") as outfile:
        json.dump(json_object, outfile, indent=2)
