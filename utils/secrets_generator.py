import argparse
from getpass import getpass
import os
from pathlib import Path
import base64
from secrets import token_hex, token_bytes
from ansible_vault import Vault
import uuid
from enum import Enum
import time
import shutil
import yaml
from textwrap import dedent
from pysodium import crypto_scalarmult_curve25519


# Generate keys as Xray-core does: https://github.com/XTLS/Xray-core/blob/main/main/commands/all/curve25519.go
# That is based on https://cr.yp.to/ecdh.html
def gen_server_keys(context):
    private_key = list(token_bytes(32))
    private_key[0] = private_key[0] & 248
    private_key[31] = private_key[31] & (127 | 64)
    private_key = bytes(private_key)
    basepoint = bytes([9] + [0] * 31)
    public_key = crypto_scalarmult_curve25519(private_key, basepoint)

    context[Token.SERVER_PRIVATE_KEY] = private_key
    context[Token.SERVER_PUBLIC_KEY] = public_key
    return private_key, public_key


def base64_urlsafe(value: bytes) -> str:
    b64 = str(base64.urlsafe_b64encode(value), "utf-8")
    while b64.endswith("="):
        b64 = b64[:-1]
    return b64


def gen_private_key(context) -> str:
    if Token.SERVER_PRIVATE_KEY not in context:
        private_key, _ = gen_server_keys(context)
    else:
        private_key = context[Token.SERVER_PRIVATE_KEY]

    return Secret(base64_urlsafe(private_key), typ=Token.SERVER_PRIVATE_KEY)


def gen_public_key(context) -> str:
    if Token.SERVER_PUBLIC_KEY not in context:
        _, public_key = gen_server_keys(context)
    else:
        public_key = context[Token.SERVER_PUBLIC_KEY]

    return Secret(base64_urlsafe(public_key), typ=Token.SERVER_PUBLIC_KEY)


def gen_sid(context, b_len: int = 8):
    if Token.SERVER_SID not in context:
        context[Token.SERVER_SID] = Secret(token_hex(b_len), typ=Token.SERVER_SID)
    return context[Token.SERVER_SID]


def gen_client_uuid(context):
    if Token.CLIENT_UUID not in context:
        context[Token.CLIENT_UUID] = Secret(str(uuid.uuid4()), typ=Token.CLIENT_UUID)
    return context[Token.CLIENT_UUID]


def gen_unsupported(*args):
    raise argparse.ArgumentTypeError("Panic! Tried to generate unsupported secret.")


class Token(Enum):
    SERVER_PRIVATE_KEY = {
        "token": "private_key",
        "generator": gen_private_key,
    }
    SERVER_PUBLIC_KEY = {
        "token": "public_key",
        "generator": gen_public_key,
    }
    SERVER_SID = {
        "token": "sid",
        "generator": gen_sid,
    }
    CLIENT_UUID = {
        "token": "uuid",
        "generator": gen_client_uuid,
    }
    UNKNOWN = {
        "token": "unknown",
        "generator": gen_unsupported,
    }

    @staticmethod
    def by_key(key: str):
        for token in Token:
            if token.value["token"] == key:
                return token
        return None


def handle_placeholder(placeholder: str, contexts: dict) -> str | None:
    if placeholder.startswith("<") and placeholder.endswith(">"):
        splits = placeholder[1:-1].split(":")
        if len(splits) != 2:
            raise argparse.ArgumentTypeError(
                "No context is specified in placeholder {}".format(placeholder)
            )
        else:
            ctx = contexts.get(splits[0], {})
            ph = Token.by_key(splits[1])
            secret = ph.value["generator"](ctx)
            return secret


def in_depth_traverse(data, contexts):
    for key, value in data.items():
        if isinstance(value, dict):
            in_depth_traverse(value, contexts)
        if isinstance(value, str):
            secret = handle_placeholder(value, contexts)
            if secret:
                log("Replacing {} with {}", value, secret)
                data[key] = secret.get()


class Verbosity(Enum):
    SILENT = 1
    VERBOSE = 2
    UNSAFE = 3


global VERBOSITY
VERBOSITY = Verbosity.SILENT


class Secret:
    def __init__(self, val: str, typ: Token = Token.UNKNOWN) -> None:
        self.value = val
        self.type = typ

    def __str__(self) -> str:
        if VERBOSITY == Verbosity.VERBOSE:
            return "{}(*****)".format(self.type.value["token"])
        if VERBOSITY == Verbosity.UNSAFE:
            return "{}({})".format(self.type.value["token"], self.value)
        return "*****"

    def get(self) -> str:
        return self.value


def log(message, *args):
    if VERBOSITY == Verbosity.SILENT:
        return
    print(message.format(*args))


def existing_file_arg(path):
    if os.path.isfile(path):
        return Path(path)
    raise argparse.ArgumentTypeError(
        "Path must target existing regular file: {}".format(path)
    )


def path_arg(path):
    return Path(path)


def output_vault_path_arg(path) -> Path:
    path = Path(path)
    if path.exists() and path.is_file():
        raise argparse.ArgumentTypeError(
            "Output vault path must not target existing regular file: {}".format(path)
        )
    if not path.parent.exists:
        raise argparse.ArgumentTypeError(
            "Output vault path parent must exist: {}".format(path.parent)
        )
    if not path.exists:
        raise argparse.ArgumentTypeError(
            "Output vault path must target existing directory or unexisting regular file: {}".format(
                path
            )
        )
    return path


def not_blank_arg(val):
    if val:
        return val
    raise argparse.ArgumentTypeError("Argument must not be blank")


def load_vault_data(path: Path, password: str, no_dec: bool = False) -> dict:
    with path.open("r") as file:
        if no_dec:
            data = yaml.safe_load(file)
            log("Loaded unencrypted vault {}", path)
        else:
            data = Vault(password).load(file)
            log("Loaded encrypted vault {}", path)
    return data


def dump_vault_data(
    path: Path, password: str, data: dict, no_enc: bool = False
) -> dict:
    with path.open("w") as file:
        if no_enc:
            yaml.safe_dump(data, file)
            log("Dumped unencrypted vault into {}", path)
        else:
            Vault(password).dump(data, file)
            log("Dumped encrypted vault into {}", path)
    return data


def handle_vault_func(args):
    vault_path: Path = args.vault_path
    vault_out_path: Path
    if args.output != None:
        vault_out_path = args.output
    else:
        vault_out_path = vault_path

    global VERBOSITY
    if args.verbose:
        VERBOSITY = Verbosity.VERBOSE
    if args.log_secrets:
        VERBOSITY = Verbosity.UNSAFE

    if args.password:
        vault_password = args.password
    elif args.password_file:
        vault_password = open(args.password_file).read()
    elif args.no_decrypt and args.no_encrypt:
        vault_password = None
    else:
        vault_password = getpass("Enter vault passphrase: ")

    data = load_vault_data(vault_path, vault_password, args.no_decrypt)
    in_depth_traverse(data, {})

    log("Done handling {} ", vault_path)

    if args.backup:
        backup_path = vault_path.parent / (
            vault_path.name + "." + str(time.time().__floor__())
        )
        shutil.copy(vault_path, backup_path)
        log("Created back up: {}", backup_path)

    dump_vault_data(vault_out_path, vault_password, data, args.no_encrypt)


def handle_vault_cli(subparsers):
    parser = subparsers.add_parser(
        "vault",
        help=dedent(
            """
        Xray server and client secrets generator for ansible vault.
        Tool can generate server public and private ECDH key pair, short id (SID) and client UUID.
        Public key generation is done by pysodium that requires libsoudium to be installed in the system.
        Tool detects placeholders for secrets to generate in the following format: <CONTEXT:TOKEN>,
          where TOKEN is one of
            - private_key - server private key;
            - public_key - server public key;
            - sid - server shord id;
            - uuid - client uuid;
          and CONTEXT is a string without white spaces that TOKEN refers to.
          Tokens refering the same context are replaced with the same value.
          If tokens private_key and public_key refer the same context, then respective keys will be corresponding. 
        """.strip()
        ),
    )
    parser.add_argument(
        "vault_path",
        help="Path to the vault to fill in",
        type=existing_file_arg,
    )

    vault_encryption_arg_group = parser.add_argument_group(
        "Vault encryption options",
        dedent(
            """
        By default, tool expects input vault to be encrypted and outputs vault encrypted.
        If both --no-decrypt and --no-encrypt options are specified, vault password below will be ignored.
        """.strip()
        ),
    )
    vault_encryption_arg_group.add_argument(
        "--no-decrypt", help="Read vault without decryption", action="store_true"
    )
    vault_encryption_arg_group.add_argument(
        "--no-encrypt", help="Output vault without encryption", action="store_true"
    )

    vault_pass_arg_group = parser.add_argument_group(
        "Vault password options",
        dedent(
            """
        You will be prompted to enter vault password 
        unless one of the options below is specified.
        """.strip()
        ),
    )
    vault_pass_arg_me_group = vault_pass_arg_group.add_mutually_exclusive_group()
    vault_pass_arg_me_group.add_argument(
        "--password", help="Pass vault password as argument", action="store"
    )
    vault_pass_arg_me_group.add_argument(
        "--password-file",
        help="Read vault password from file; file must contain one line with password",
        type=existing_file_arg,
    )

    logs_arg_group = parser.add_argument_group(
        "Verbosity options",
        "By default, tool is almost silent and prints minimal number of logs.",
    )
    logs_arg_group.add_argument(
        "-v",
        "--verbose",
        help="Print logs",
        action="store_true",
    )
    logs_arg_group.add_argument(
        "--log-secrets",
        help="Print secrets without replacing them with *****",
        action="store_true",
    )
    parser.add_argument(
        "-b",
        "--backup",
        help="Backup vault before doing any modifications",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output resulting data into different file",
        type=output_vault_path_arg,
    )

    parser.set_defaults(func=handle_vault_func)


def gen_server_keys_func(_):
    private_key, public_key = gen_server_keys({})
    print("Private key: {}".format(base64_urlsafe(private_key)))
    print("Public key: {}".format(base64_urlsafe(public_key)))


def gen_server_keys_cli(subparsers):
    parser = subparsers.add_parser(
        "x25519",
        help=dedent(
            """
            Generate Xray server private and public keys.
            Default output is corresponding to the xray-core x25519 command.
            """.strip()
        ),
    )
    parser.set_defaults(func=gen_server_keys_func)


def sid_arg(v):
    v = int(v)
    if v <= 0 or v > 8:
        raise argparse.ArgumentTypeError("Sid must be in range [1;8]")
    return v


def gen_server_sid_cli(subparsers):
    func = lambda args: print(gen_sid({}, args.length).get())

    parser = subparsers.add_parser(
        "sid",
        help=dedent("Generate Xray server SID (Short ID)."),
    )
    parser.add_argument(
        "-l",
        "--length",
        help="SID length in bytes (max 8)",
        type=sid_arg,
        default=8,
    )
    parser.set_defaults(func=func)


def gen_client_uuid_cli(subparsers):
    func = lambda args: print(gen_client_uuid({}).get())

    parser = subparsers.add_parser(
        "uuid",
        help=dedent("Generate Client UUID."),
    )
    parser.set_defaults(func=func)


def cli():
    parser = argparse.ArgumentParser(
        prog="Xray secrets generator",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    subparsers = parser.add_subparsers(required=True)
    handle_vault_cli(subparsers)
    gen_server_keys_cli(subparsers)
    gen_server_sid_cli(subparsers)
    gen_client_uuid_cli(subparsers)

    return parser.parse_args()


def main():
    args = cli()
    args.func(args)


if __name__ == "__main__":
    main()
