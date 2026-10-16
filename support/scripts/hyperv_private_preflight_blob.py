#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded Blob worker for the private Hyper-V platform preflight."""

import argparse
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import re
import stat


SCHEMA = "unikraft.hyperv.private-preflight-blob-worker"
SDK_VERSION = "12.28.0"
MAX_REQUEST_BYTES = 256 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
BLOB_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}")
CONTAINER = re.compile(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?")
ACCOUNT_URL = re.compile(
    r"https://[a-z0-9]{3,24}\.blob\.core\.windows\.net"
)
ALLOWLISTED_STAGES = frozenset((
    "request",
    "sdk",
    "create-container",
    "upload-blob",
    "download-blob",
    "worker",
))
ALLOWLISTED_CATEGORIES = frozenset((
    "invalid-request-fields",
    "duplicate-json-field",
    "malformed-request",
    "invalid-request",
    "invalid-local-path",
    "invalid-blob-name",
    "invalid-size",
    "invalid-sha256",
    "invalid-local-input",
    "invalid-request-file",
    "invalid-request-contract",
    "invalid-output-directory",
    "download-size-limit",
    "invalid-sas",
    "missing-sas",
    "local-io-error",
    "sdk-version-mismatch",
    "sdk-unavailable",
    "authentication-failed",
    "resource-not-found",
    "resource-exists",
    "http-response-error",
    "service-request-error",
    "service-response-error",
    "blob-operation-failed",
    "worker-output-invalid",
    "worker-process-failed",
))
ALLOWLISTED_SERVICE_ERROR_CODES = frozenset((
    "AccountIsDisabled",
    "AuthenticationFailed",
    "AuthorizationFailure",
    "AuthorizationPermissionMismatch",
    "AuthorizationProtocolMismatch",
    "AuthorizationResourceTypeMismatch",
    "AuthorizationServiceMismatch",
    "AuthorizationSourceIPMismatch",
    "BlobAlreadyExists",
    "BlobArchived",
    "BlobBeingRehydrated",
    "BlobImmutableDueToLegalHold",
    "BlobImmutableDueToPolicy",
    "BlobNotFound",
    "CannotVerifyCopySource",
    "ConditionHeadersNotSupported",
    "ConditionNotMet",
    "ContainerAlreadyExists",
    "ContainerBeingDeleted",
    "ContainerDisabled",
    "ContainerNotFound",
    "EmptyMetadataKey",
    "InsufficientAccountPermissions",
    "InternalError",
    "InvalidAuthenticationInfo",
    "InvalidBlobOrBlock",
    "InvalidBlobTier",
    "InvalidBlobType",
    "InvalidBlockId",
    "InvalidBlockList",
    "InvalidHeaderValue",
    "InvalidHttpVerb",
    "InvalidInput",
    "InvalidMd5",
    "InvalidMetadata",
    "InvalidOperation",
    "InvalidQueryParameterValue",
    "InvalidRange",
    "InvalidResourceName",
    "InvalidUri",
    "InvalidVersionForPageBlobOperation",
    "InvalidXmlDocument",
    "InvalidXmlNodeValue",
    "LeaseIdMismatchWithBlobOperation",
    "LeaseIdMismatchWithContainerOperation",
    "LeaseIdMismatchWithLeaseOperation",
    "LeaseIdMissing",
    "LeaseIsBrokenAndCannotBeRenewed",
    "LeaseIsBreakingAndCannotBeAcquired",
    "LeaseLost",
    "LeaseNotPresentWithBlobOperation",
    "LeaseNotPresentWithContainerOperation",
    "LeaseNotPresentWithLeaseOperation",
    "MaxBlobSizeConditionNotMet",
    "Md5Mismatch",
    "MetadataTooLarge",
    "MissingContentLengthHeader",
    "MissingRequiredHeader",
    "MissingRequiredQueryParameter",
    "MissingRequiredXmlNode",
    "MultipleConditionHeadersNotSupported",
    "NoAuthenticationInformation",
    "NoPendingCopyOperation",
    "OperationNotAllowedOnIncrementalCopyBlob",
    "OperationTimedOut",
    "OutOfRangeInput",
    "OutOfRangeQueryParameterValue",
    "PendingCopyOperation",
    "PreviousSnapshotCannotBeNewer",
    "PublicAccessNotPermitted",
    "RequestBodyTooLarge",
    "RequestUrlFailedToParse",
    "ResourceAlreadyExists",
    "ResourceNotFound",
    "ResourceTypeMismatch",
    "SequenceNumberConditionNotMet",
    "SequenceNumberTooLarge",
    "ServerBusy",
    "SnapshotCountExceeded",
    "SnapshotOperationRateExceeded",
    "SnapshotsPresent",
    "SourceConditionNotMet",
    "SystemInUse",
    "TargetConditionNotMet",
    "UnauthorizedBlobOverwrite",
    "UnsupportedHeader",
    "UnsupportedHttpVerb",
    "UnsupportedQueryParameter",
    "UnsupportedXmlNode",
))


class WorkerError(RuntimeError):
    def __init__(
        self, category, *, stage="request", http_status=None,
        service_error=None,
    ):
        if stage not in ALLOWLISTED_STAGES:
            stage = "request"
        if category not in ALLOWLISTED_CATEGORIES:
            category = "blob-operation-failed"
        if (
            type(http_status) is not int
            or not 100 <= http_status <= 599
        ):
            http_status = None
        if (
            not isinstance(service_error, str)
            or service_error not in ALLOWLISTED_SERVICE_ERROR_CODES
        ):
            service_error = None
        super().__init__(category)
        self.stage = stage
        self.category = category
        self.http_status = http_status
        self.service_error = service_error

    def to_payload(self):
        return {
            "schema": 1,
            "result": "FAIL",
            "stage": self.stage,
            "category": self.category,
            "http_status": self.http_status,
            "service_error": self.service_error,
        }


def extract_http_status(error):
    for candidate in (
        getattr(error, "status_code", None),
        getattr(getattr(error, "response", None), "status_code", None),
    ):
        if type(candidate) is int and 100 <= candidate <= 599:
            return candidate
    return None


def extract_service_error(error):
    candidates = [
        getattr(error, "error_code", None),
        getattr(getattr(error, "error", None), "code", None),
    ]
    headers = getattr(getattr(error, "response", None), "headers", None)
    if hasattr(headers, "get"):
        candidates.append(headers.get("x-ms-error-code"))
        candidates.append(headers.get("X-Ms-Error-Code"))
    for candidate in candidates:
        value = getattr(candidate, "value", candidate)
        if (
            isinstance(value, str)
            and value in ALLOWLISTED_SERVICE_ERROR_CODES
        ):
            return value
    return None


def classify_azure_error(error, stage):
    class_names = {cls.__name__ for cls in type(error).__mro__}
    if "ClientAuthenticationError" in class_names:
        category = "authentication-failed"
    elif "ResourceNotFoundError" in class_names:
        category = "resource-not-found"
    elif "ResourceExistsError" in class_names:
        category = "resource-exists"
    elif "ServiceRequestError" in class_names:
        category = "service-request-error"
    elif "ServiceResponseError" in class_names:
        category = "service-response-error"
    elif "HttpResponseError" in class_names:
        category = "http-response-error"
    else:
        category = "blob-operation-failed"
    return WorkerError(
        category,
        stage=stage,
        http_status=extract_http_status(error),
        service_error=extract_service_error(error),
    )


def exact_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise WorkerError("invalid-request-fields")
    return value


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WorkerError("duplicate-json-field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise WorkerError("malformed-request") from None
    if not isinstance(value, dict):
        raise WorkerError("invalid-request")
    return value


def require_path(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise WorkerError("invalid-local-path")
    path = Path(value)
    if not path.is_absolute():
        raise WorkerError("invalid-local-path")
    return path


def require_blob(value):
    if (
        not isinstance(value, str)
        or not BLOB_NAME.fullmatch(value)
        or value.startswith("/")
        or ".." in Path(value).parts
    ):
        raise WorkerError("invalid-blob-name")
    return value


def require_nonnegative(value, maximum=MAX_FILE_BYTES):
    if type(value) is not int or not 0 <= value <= maximum:
        raise WorkerError("invalid-size")
    return value


def require_sha256(value):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise WorkerError("invalid-sha256")
    return value


def regular_fingerprint(path, expected_size, expected_sha256):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise WorkerError("invalid-local-input") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != expected_size
        ):
            raise WorkerError("invalid-local-input")
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining or os.read(descriptor, 1):
            raise WorkerError("invalid-local-input")
        if digest.hexdigest() != expected_sha256:
            raise WorkerError("invalid-local-input")
    finally:
        os.close(descriptor)


def load_request(path):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise WorkerError("invalid-request-file") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or metadata.st_size > MAX_REQUEST_BYTES
        ):
            raise WorkerError("invalid-request-file")
        raw = os.read(descriptor, MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES or os.read(descriptor, 1):
            raise WorkerError("invalid-request-file")
    finally:
        os.close(descriptor)
    request = exact_fields(
        strict_json(raw),
        (
            "schema", "schema_version", "action", "account_url",
            "container", "files", "create_container",
        ),
    )
    if (
        request["schema"] != SCHEMA
        or type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or request["action"] not in ("upload", "download")
        or not isinstance(request["account_url"], str)
        or not ACCOUNT_URL.fullmatch(request["account_url"])
        or not isinstance(request["container"], str)
        or not CONTAINER.fullmatch(request["container"])
        or type(request["create_container"]) is not bool
        or not isinstance(request["files"], list)
        or not request["files"]
        or len(request["files"]) > 128
        or (
            request["action"] == "download"
            and request["create_container"] is not False
        )
    ):
        raise WorkerError("invalid-request-contract")
    return request


def upload(client, request, azure_error_type=()):
    total = 0
    if request["create_container"]:
        try:
            client.create_container(timeout=60)
        except WorkerError:
            raise
        except azure_error_type as error:
            raise classify_azure_error(error, "create-container") from None
    for raw in request["files"]:
        record = exact_fields(
            raw, ("blob", "path", "size", "sha256")
        )
        blob = require_blob(record["blob"])
        path = require_path(record["path"])
        size = require_nonnegative(record["size"])
        digest = require_sha256(record["sha256"])
        regular_fingerprint(path, size, digest)
        with path.open("rb") as source:
            try:
                client.upload_blob(
                    name=blob,
                    data=source,
                    length=size,
                    overwrite=False,
                    validate_content=True,
                    max_concurrency=1,
                    timeout=300,
                )
            except WorkerError:
                raise
            except azure_error_type as error:
                raise classify_azure_error(error, "upload-blob") from None
        regular_fingerprint(path, size, digest)
        total += size
    return total


def download(client, request, azure_error_type=()):
    total = 0
    for raw in request["files"]:
        record = exact_fields(raw, ("blob", "path", "maximum"))
        blob = require_blob(record["blob"])
        path = require_path(record["path"])
        maximum = require_nonnegative(record["maximum"])
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise WorkerError("invalid-output-directory")
        try:
            downloader = client.download_blob(
                blob, max_concurrency=1, timeout=300
            )
            written = 0
            digest = hashlib.sha256()
            try:
                with path.open("xb") as output:
                    os.chmod(path, 0o600)
                    for chunk in downloader.chunks():
                        written += len(chunk)
                        if written > maximum:
                            raise WorkerError("download-size-limit")
                        output.write(chunk)
                        digest.update(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        except WorkerError:
            raise
        except azure_error_type as error:
            raise classify_azure_error(error, "download-blob") from None
        total += written
    return total


def execute(request, sas):
    if (
        not isinstance(sas, str)
        or not sas
        or len(sas.encode()) > 4096
        or any(character.isspace() for character in sas)
    ):
        raise WorkerError("invalid-sas")
    try:
        if version("azure-storage-blob") != SDK_VERSION:
            raise WorkerError("sdk-version-mismatch", stage="sdk")
    except PackageNotFoundError:
        raise WorkerError("sdk-unavailable", stage="sdk") from None
    try:
        from azure.core.exceptions import AzureError
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        raise WorkerError("sdk-unavailable", stage="sdk") from None
    try:
        service = BlobServiceClient(
            account_url=request["account_url"],
            credential=sas,
            retry_total=0,
            connection_timeout=30,
            read_timeout=60,
        )
        client = service.get_container_client(request["container"])
        if request["action"] == "upload":
            return upload(client, request, AzureError)
        return download(client, request, AzureError)
    except WorkerError:
        raise
    except AzureError as error:
        fallback_stage = (
            "upload-blob"
            if request["action"] == "upload"
            else "download-blob"
        )
        raise classify_azure_error(error, fallback_stage) from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        request = load_request(args.request)
        sas = os.environ.pop("HYPERV_PREFLIGHT_SAS")
        transferred = execute(request, sas)
        print(json.dumps({
            "schema": 1,
            "result": "PASS",
            "bytes": transferred,
        }, sort_keys=True))
    except WorkerError as error:
        print(json.dumps(error.to_payload(), sort_keys=True))
        raise SystemExit(1)
    except KeyError:
        print(json.dumps(
            WorkerError("missing-sas", stage="request").to_payload(),
            sort_keys=True,
        ))
        raise SystemExit(1)
    except OSError:
        print(json.dumps(
            WorkerError("local-io-error", stage="request").to_payload(),
            sort_keys=True,
        ))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
