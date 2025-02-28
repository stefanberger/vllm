# SPDX-License-Identifier: Apache-2.0

# Standard
import glob
from pathlib import Path
from typing import List, Optional
from os.path import join

# Third Party
from cryptography.x509 import (
    ExtensionNotFound,
    RFC822Name,
    SubjectAlternativeName,
)
from sigstore.oidc import Issuer
from sigstore import models
from sigstore.verify.policy import OIDCIssuer
from model_signing import model
from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.signing import in_toto
from model_signing.signing import sign_sigstore as sigstore


def _create_git_related_files(model_path: Path) -> List[str]:
    return glob.glob(join(model_path, '.git*'))


# Create a list of ignored paths; include git related files there
def _create_ignored_paths(paths: List[str], model_path: Path) -> List[str]:
    return paths + _create_git_related_files(model_path)


def confirm(msg: str, yes: bool) -> bool:
    """ Have the user respond to a message with either y or n"""
    while True:
        print(msg, end='')
        if yes:
            print("y\n")
            return True
        answer = input("")
        if answer in ['y', 'Y']:
            return True
        if answer in ['n', 'N']:
            return False


def get_oidc_params_from_sigfile(sigfile: Path) -> (Optional[str], Optional[str]):
    """Get the OIDC parameters of email and issuer from the in-toto signature file"""
    data = sigfile.read_text()
    bundle = models.Bundle.from_json(data)

    signing_cert = bundle.signing_certificate
    # SAN holds the identity's email
    san_ext = signing_cert.extensions.get_extension_for_class(SubjectAlternativeName).value
    all_sans = san_ext.get_values_for_type(RFC822Name)
    if len(all_sans) != 1:
        raise ValueError(f"Expected to find 1 email address in certificate's SAN: {all_sans}")

    try:
        ext = signing_cert.extensions.get_extension_for_oid(OIDCIssuer.oid).value
    except ExtensionNotFound as ex:
        raise ValueError(f"Could not get issuer from certificate extension {OIDCIssuer.oid}") from ex
    return all_sans[0], ext.value.decode()


def sign_model(
    model_path: Path,
    sig_out: Path,
    use_ambient_credentials: bool,
    identity_token: Optional[str] = None
) -> None:
    """Signs a model with Sigstore"""

    def hasher_factory(file_path: Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_file.ManifestSerializer(
        file_hasher_factory=hasher_factory
    )

    if not identity_token:
        issuer = Issuer.production()
        identity_token = issuer.identity_token()

    payload_signer = sigstore.SigstoreDSSESigner(
        use_ambient_credentials=use_ambient_credentials,
        use_staging=False,
        identity_token=identity_token,
    )

    sig = model.sign(
        model_path=model_path,
        signer=payload_signer,
        payload_generator=in_toto.DigestsIntotoPayload.from_manifest,
        serializer=serializer,
        ignore_paths=_create_ignored_paths([sig_out], model_path)
    )

    sig.write(sig_out)
    print(f"Wrote signature to {sig_out}.")


def verify_model(
    model_path: Path,
    signature_file: Path,
    identity: str,
    issuer: str,
) -> None:
    """Verifies a model and its bundle with Sigstore"""

    verifier = sigstore.SigstoreDSSEVerifier(
        identity=identity, oidc_issuer=issuer
    )
    sig = sigstore.SigstoreSignature.read(signature_file)
    def hasher_factory(file_path: Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path, content_hasher=memory.SHA256()
        )

    serializer = serialize_by_file.ManifestSerializer(
        file_hasher_factory=hasher_factory
    )
    model.verify(
        sig=sig,
        verifier=verifier,
        model_path=model_path,
        serializer=serializer,
        ignore_paths=_create_ignored_paths([signature_file], model_path)
    )
