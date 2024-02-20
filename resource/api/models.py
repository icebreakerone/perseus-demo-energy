import datetime
from pydantic import BaseModel, Field

class Consumption(BaseModel):
    value: float
    unitCode: str

class Reading(BaseModel):
    type: str
    from_: datetime.datetime = Field(None, alias="from")
    to: datetime.datetime
    consumption: Consumption

class MeterData(BaseModel):
    data: list[Reading]

