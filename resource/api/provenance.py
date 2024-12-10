"""
Placeholder for provenance records
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import datetime

from ib1.provenance import Record
from ib1.provenance.signing import SignerFiles, SignerInMemory
from ib1.provenance.certificates import (
    CertificatesProviderSelfContainedRecord,
)
from ib1.directory.certificates import load_key
from . import conf


TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"


def create_provenance_records(
    from_date: datetime.date,
    to_date: datetime.date,
    permission_granted: datetime.datetime,
    permission_expires: datetime.datetime,
    service_url: str,
    account: str,
    fapi_id: str = "C25D0B85-B7C4-4543-B058-7DA57B8D9A24",
    cap_member: str = "https://directory.core.trust.ib1.org/member/81524",
) -> bytes:
    certificate_provider = CertificatesProviderSelfContainedRecord(
        f"{conf.ROOT_DIR}/certs/smart-meter-data-download-cert.pem"
    )
    with open(
        f"{conf.ROOT_DIR}/certs/smart-meter-data-download-bundle.pem", "rb"
    ) as certs:
        signer_edp_certs = x509.load_pem_x509_certificates(certs.read())
    signer_edp = SignerInMemory(
        certificate_provider,
        signer_edp_certs,  # list containing certificate and issuer chain
        load_key(conf.SIGNING_KEY.encode("utf-8")),  # private key
    )

    edp_record = Record(TRUST_FRAMEWORK_URL)
    # - Permission step to record consent by end user
    edp_permission_id = edp_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "timestamp": permission_granted,
            "account": account,
            "allows": {
                "licences": [
                    "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05"
                ]
            },
            "expires": permission_expires,
        }
    )
    origin_id = edp_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "sourceType": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/source-type/Meter",
            "origin": "https://www.smartdcc.co.uk/",
            "originLicence": "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
            "external": True,
            "permissions": [edp_permission_id],
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": f"{from_date.isoformat()}Z",
                    "to": f"{to_date.isoformat()}Z",
                }
            },
            "perseus:assurance": {  # TODO add logic to select correct assurance
                "dataSource": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/data-source/SmartMeter",
                "missingData": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/missing-data/Missing",
                "processing": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/processing/SmartDCCOtherUser",
            },
        }
    )

    # - Transfer step to send it to the CAP
    edp_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "of": origin_id,
            "to": cap_member,
            "standard": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/standard/energy-consumption-data/2024-12-05",
            "licence": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05",
            "service": service_url,
            "path": "/readings",
            "parameters": {
                "measure": "import",
                "from": f"{from_date.isoformat()}Z",
                "to": f"{to_date.isoformat()}Z",
            },
            "permissions": [edp_permission_id],
            "transaction": fapi_id,
        }
    )

    # EDP signs the steps
    edp_record_signed = edp_record.sign(signer_edp)
    edp_record_signed.verify(certificate_provider)
    # Get encoded data for inclusion in data response
    edp_data_attachment = edp_record_signed.encoded()
    return edp_data_attachment
