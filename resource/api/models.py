import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Measure(str, Enum):
    """
    The measures this data source can return.

    One list serves both purposes: /datasources advertises it, and FastAPI
    validates the path parameter against it and publishes the allowed values
    in the OpenAPI schema.
    """

    IMPORT = "import"
    EXPORT = "export"


class EnergyType(str, Enum):
    """
    The kinds of data source the scheme defines. Lower case, as the registry's
    consumption-data API declares them.
    """

    ELECTRICITY = "electricity"
    GAS = "gas"


class UnitCode(str, Enum):
    """
    CEFACT unit codes the registry API permits. MTQ, cubic metres, is gas only.
    """

    KWH = "KWH"
    WHR = "WHR"
    MTQ = "MTQ"


class ApiErrorResponse(BaseModel):
    """
    Error response carrying an RFC 6750 error code.
    """

    error: str
    error_description: str | None = None


class Consumption(BaseModel):
    value: float = Field(ge=0)
    unitCode: UnitCode


class Reading(BaseModel):
    type: EnergyType
    from_date: datetime.datetime = Field(alias="from")
    to_date: datetime.datetime = Field(alias="to")
    takenAt: datetime.datetime
    energy: Consumption
    cumulative: Consumption


class Datasource(BaseModel):
    id: str
    type: EnergyType
    location: dict
    availableMeasures: list[Measure]


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
                            "type": "electricity",
                            "from": "2023-10-18T00:00:00Z",
                            "to": "2023-10-18T00:30:00Z",
                            "takenAt": "2023-10-18T01:00:00Z",
                            "energy": {"value": 123.45, "unitCode": "WHR"},
                            "cumulative": {"value": 1234.5, "unitCode": "WHR"},
                        },
                    ],
                    "location": {"ukPostcodeOutcode": "SW8"},
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
