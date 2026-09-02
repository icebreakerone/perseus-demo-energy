import datetime

from cryptography import x509

from ib1.provenance import Record
from ib1.provenance.signing import SignerInMemory
from ib1.provenance.certificates import (
    CertificatesProviderSelfContainedRecord,
)
from . import conf
from .keystores import get_key, get_certificate


def _date_to_iso(date: datetime.date) -> str:
    return f"{date.isoformat()}T00:00Z"


def create_provenance_records(
    from_date: datetime.date,
    to_date: datetime.date,
    permission_granted: datetime.datetime,
    permission_expires: datetime.datetime,
    service_url: str,
    account: str,
    cap_member: str,
    license_url: str,
) -> bytes:

    certificate_provider = CertificatesProviderSelfContainedRecord(
        get_certificate(conf.SIGNING_ROOT_CA_CERTIFICATE)
    )
    signer_edp_certs = x509.load_pem_x509_certificates(
        get_certificate(conf.SIGNING_BUNDLE)
    )
    private_key = get_key(conf.SIGNING_KEY)
    signer_edp = SignerInMemory(
        certificate_provider,
        signer_edp_certs,  # list containing certificate and issuer chain
        private_key,  # private key
    )

    edp_record = Record(conf.TRUST_FRAMEWORK_URL)
    # - Permission step to record consent by end user
    edp_permission_id = edp_record.add_step(
        {
            "type": "permission",
            "scheme": conf.SCHEME_BASE_URL,
            "timestamp": f"{permission_granted.isoformat()[0:-7]}Z",
            "account": account,
            "allows": {"licenses": [license_url]},
            "expires": f"{permission_expires.isoformat()[0:-7]}Z",
        }
    )
    origin_id = edp_record.add_step(
        {
            "type": "origin",
            "scheme": conf.SCHEME_BASE_URL,
            "sourceType": f"{conf.SCHEME_BASE_URL}/source-type/Meter",
            "origin": "https://www.smartdcc.co.uk/",
            "originLicense": "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
            "external": True,
            "permissions": [edp_permission_id],
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": _date_to_iso(from_date),
                    "to": _date_to_iso(to_date),
                }
            },
            "perseus:assurance": {  # TODO add logic to select correct assurance
                "missingData": f"{conf.SCHEME_BASE_URL}/assurance/missing-data/Missing",
                "originMethod": f"{conf.SCHEME_BASE_URL}/assurance/origin-method/SmartDCCOtherUser",
            },
        }
    )

    # - Transfer step to send it to the CAP
    edp_record.add_step(
        {
            "type": "transfer",
            "scheme": conf.SCHEME_BASE_URL,
            "of": origin_id,
            "to": cap_member,
            "standard": f"{conf.SCHEME_BASE_URL}/standard/energy-consumption-data/2026-03-12",
            "license": license_url,
            "service": service_url,
            "path": "/readings",
            "parameters": {
                "measure": "import",
                "from": _date_to_iso(from_date),
                "to": _date_to_iso(to_date),
            },
            "permissions": [edp_permission_id],
        }
    )

    # EDP signs the steps
    edp_record_signed = edp_record.sign(signer_edp)
    # edp_record_signed.verify(certificate_provider)
    # Get encoded data for inclusion in data response
    edp_data_attachment = edp_record_signed.encoded()
    return edp_data_attachment
