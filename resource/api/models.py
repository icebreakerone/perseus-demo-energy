import datetime
from pydantic import BaseModel, Field


class Consumption(BaseModel):
    value: float
    unitCode: str


class Reading(BaseModel):
    type: str
    from_date: datetime.datetime = Field(alias="from")
    to_date: datetime.datetime = Field(alias="to")
    takenAt: datetime.datetime
    energy: Consumption
    cumulative: Consumption


class Datasource(BaseModel):
    id: str
    type: str
    location: dict
    availableMeasures: list[str]


class Datasources(BaseModel):
    data: list[Datasource]


class MeterData(BaseModel):
    data: list[Reading]
    location: dict
    provenance: dict
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "data": [
                        {
                            "type": "Electricity",
                            "from": "2023-10-18T00:00:00Z",
                            "to": "2023-10-18T00:30:00Z",
                            "takenAt": "2023-10-19T00:00:00Z",
                            "energy": {"value": 123.45, "unitCode": "WHR"},
                            "cumulative": {"value": 1234.5, "unitCode": "WHR"},
                        },
                    ],
                    "provenance": [
                        [
                            "eyJpZCI6IlVSZDB3Z3MiLCJ0eXBlIjoidHJhbnNmZXIiLCJmcm9tIjoiaHR0cHM6...MyOjU2WiJ9",
                            "eyJpZCI6Iml0SU5zR3RVIiwidHlwZSI6InJlY2VpcHQiLCJmcm9tIjoiaHR0c...jE2OjMxWiJ9",
                            [
                                "123456",
                                "2024-10-17T12:16:31Z",
                                "MEUCIQDNk3nS64bmGvMJwfdVWfyGuheGDEbB8-b5Ur2H9Iat9gIgc...eGO3GvzH2EJut707lA=",
                            ],
                        ],
                    ],
                }
            ]
        }
    }
