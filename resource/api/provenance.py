"""
Placeholder for provenance records
"""


class Record:
    def __init__(self):
        pass

    def add_step(self, type: dict):
        pass

    def add_record(self):
        pass

    def sign(self):
        pass

    def encode(self) -> list:
        return [
            [
                "eyJpZCI6IlVSZDB3Z3MiLCJ0eXBlIjoidHJhbnNmZXIiLCJmcm9tIjoiaHR0cHM6……...MyOjU2WiJ9",
                "eyJpZCI6Iml0SU5zR3RVIiwidHlwZSI6InJlY2VpcHQiLCJmcm9tIjoiaHR0cH………..jE2OjMxWiJ9",
                [
                    "123456",
                    "2024-10-17T12:16:31Z",
                    "MEUCIQDNk3nS64bmGvMJwfdVWfyGuheGDEbB8-b5Ur2H9Iat9gIgc……..eGO3GvzH2EJut707lA=",
                ],
            ],
        ]

    def decode(self):
        pass
