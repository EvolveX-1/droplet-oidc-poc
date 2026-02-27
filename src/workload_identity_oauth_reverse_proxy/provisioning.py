import sys
import uuid
import socket
import secrets
import pathlib
import tempfile
import textwrap
import subprocess
import contextlib
import dataclasses
import importlib.resources

import yaml
import paramiko


from . import do_api
from . import oidc_helper
from . import oauth_helper
from . import database
from .common import THIS_ENDPOINT


DEFAULT_NONCE_LEN = 64
# Max 15 minutes to spin up in case of long user_data scripts
DEFAULT_TTL_SECONDS = 60 * 15


@dataclasses.dataclass
class ProvisioningData:
    nonce: str
    token: oidc_helper.OIDCToken
    user_data: str

    @classmethod
    def create(
        cls,
        team_uuid: uuid.UUID,
        user_data: str | None,
        *,
        ttl: int | None = None,
        nonce_len: int | None = None,
    ) -> "ProvisioningData":
        global THIS_ENDPOINT

        if user_data is None:
            user_data = ""

        if nonce_len is None:
            nonce_len = DEFAULT_NONCE_LEN
        nonce = secrets.token_hex(nonce_len)

        if ttl is None:
            ttl = DEFAULT_TTL_SECONDS

        token = oidc_helper.OIDCToken.create(str(team_uuid), {"nonce": nonce, "sub": f"actx:{team_uuid}:role:provisioning:nonce:{nonce}", "ttl": ttl},
        )

        # TODO Handle case where user_data is script
        user_data_obj = {}
        with contextlib.suppress(Exception):
            user_data_obj = yaml.safe_load(user_data)
        if not user_data_obj:
            user_data_obj = {}
        user_data_obj.setdefault("runcmd", []).append(
            textwrap.dedent(
                f"""
                set -eu
                TEAM_UUID="{team_uuid}"
                THIS_ENDPOINT="{THIS_ENDPOINT}"
                PROVISIONING_TOKEN="{token.as_string}"
                """.strip(
                    "\n"
                ),
            )
            + importlib.resources.read_text(__package__, "cloud-init.sh")
        )

        user_data = "\n".join(["#cloud-config", yaml.dump(user_data_obj)])

        return ProvisioningData(
            nonce=nonce,
            token=token,
            user_data=user_data,
        )

    def associate_with_droplet(self, droplet_id: int) -> None:
        # Upstream API create threw error
        if droplet_id < 1:
            return

        database.create_provisioning_nonce(self.nonce, droplet_id)


def get_droplet_id(nonce: str) -> int:
    return database.get_provisioning_nonce_droplet_id(nonce)


def get_public_key_from_port(public_ipv4: str, port: int) -> str:
    # Get the server's public key by connecting to a port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.connect((public_ipv4, port))
        return sock.recv(2**14).decode()


def get_public_key_from_sshd(public_ipv4: str, port: int) -> str:
    # https://www.digitalocean.com/community/questions/ssh-from-digital-ocean-app-platform
    # This is not allowed when running under App Platform
    # Get the server's public key by connecting to it's SSHD
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.connect((public_ipv4, port))

        with contextlib.closing(paramiko.Transport(sock)) as transport:
            transport.start_client(timeout=20)
            server_public_key = transport.get_remote_server_key()
            return f"{server_public_key.get_name()} {server_public_key.get_base64()}"


def validate_ssh_signature(
    public_key_openssh_string: str, ssh_signature_blob: str, data_that_was_signed: str
) -> bool:
    # Verify the signature was signed by the private key using the public key
    with tempfile.TemporaryDirectory() as tempdir:
        pathlib.Path(tempdir, "allowed_signing_key.pub").write_text(
            public_key_openssh_string
        )
        pathlib.Path(tempdir, "signature").write_text(ssh_signature_blob)
        data_path = pathlib.Path(tempdir, "data")
        data_path.write_text(data_that_was_signed)

        with open(data_path.resolve(), "rb") as data_fileobj:
            proc = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "check-novalidate",
                    "-n",
                    "prove-sshd",
                    "-f",
                    "allowed_signing_key.pub",
                    "-s",
                    "signature",
                ],
                check=False,
                cwd=tempdir,
                stdin=data_fileobj,
                stdout=subprocess.DEVNULL,
            )
    return proc.returncode == 0


def validate(
    token: str,
    signature: str,
    port: int,
) -> tuple[oidc_helper.OIDCToken, dict] | tuple[None, None]:
    oidc_token = oidc_helper.OIDCToken.validate(token)

    team_token = oauth_helper.retrieve_oauth_token(oidc_token.actx)

    droplet_id = get_droplet_id(oidc_token.claims["nonce"])

    droplet = do_api.do_droplet_get(team_token, droplet_id)

    public_ipv4 = [
        ipv4["ip_address"]
        for ipv4 in droplet["networks"]["v4"]
        if ipv4["type"] == "public"
    ][0]

    public_key = get_public_key_from_port(public_ipv4, port)

    try:
        valid = validate_ssh_signature(
            public_key,
            signature,
            token,
        )
    except Exception as e:
        raise Exception("Failed to validate SSHD signature") from e

    if not valid:
        return None, None

    return oidc_token, droplet


if __name__ == "__main__":
    valid = validate_ssh_signature(*sys.argv[1:])
    if valid:
        print("Valid")
        sys.exit(0)
    else:
        print("INVALID")
        sys.exit(1)
