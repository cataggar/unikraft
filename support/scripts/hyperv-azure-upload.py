#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


PAGE_CHUNK = 4 * 1024 * 1024


def storage_sdk():
    try:
        from azure.core.exceptions import AzureError
        from azure.storage.blob import BlobClient
    except ImportError as error:
        raise RuntimeError(
            "Azure Blob SDK is required; install support/azure/requirements.txt "
            "in the Python environment running this controller"
        ) from error
    return BlobClient, AzureError


def upload_pages(image, endpoint, sas):
    if urlsplit(endpoint).query or urlsplit(endpoint).fragment:
        raise ValueError("The upload endpoint must not contain a query or fragment")
    controller = importlib.import_module("hyperv-azure")
    controller.upload_endpoint(endpoint + "?" + sas)
    blob_client, azure_error = storage_sdk()
    if image.is_symlink() or not image.is_file():
        raise ValueError("Upload input must be a regular, non-symlink file")
    with image.open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        image_digest = hashlib.sha256()
        if size < 512 or size % 512:
            raise ValueError(
                "Managed-disk upload must contain complete 512-byte pages"
            )
        source.seek(size - 512)
        expected_footer = source.read(512)
        source.seek(0)
        try:
            with blob_client.from_blob_url(
                endpoint, credential=sas, api_version="2020-10-02",
                retry_total=0, connection_timeout=30, read_timeout=30,
                logging_enable=False,
            ) as client:
                for offset in range(0, size, PAGE_CHUNK):
                    length = min(PAGE_CHUNK, size - offset)
                    page = source.read(length)
                    if len(page) != length:
                        raise ValueError(
                            "Upload input became shorter during transfer"
                        )
                    image_digest.update(page)
                    client.upload_page(
                        page, offset, length, validate_content=True
                    )
                if source.read(1):
                    raise ValueError("Upload input grew during transfer")
                footer = client.download_blob(
                    offset=size - 512, length=512, validate_content=True,
                    max_concurrency=1,
                ).readall()
        except azure_error as error:
            code = getattr(error, "error_code", None)
            if (
                not isinstance(code, str)
                or not re.fullmatch(r"[A-Za-z0-9_]+", code)
            ):
                code = type(error).__name__
            raise RuntimeError(f"Managed-disk page transfer failed: {code}") from None
    if footer != expected_footer:
        raise ValueError("Uploaded VHD footer does not match the local image")
    return {
        "uploaded_bytes": size,
        "image_sha256": image_digest.hexdigest(),
        "footer_matches": True,
        "footer_sha256": hashlib.sha256(footer).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Bounded page updates for an already-created Azure managed disk"
    )
    parser.add_argument("--check-dependencies", action="store_true")
    parser.add_argument("--image", type=Path)
    parser.add_argument("--endpoint")
    args = parser.parse_args()
    try:
        if args.check_dependencies:
            storage_sdk()
            print(json.dumps({"available": True}))
            return
        if args.image is None or not args.endpoint:
            parser.error("--image and --endpoint are required for upload")
        sas = os.environ.get("AZURE_STORAGE_SAS_TOKEN")
        if not sas:
            raise ValueError("AZURE_STORAGE_SAS_TOKEN must contain the write SAS")
        print(json.dumps(upload_pages(args.image, args.endpoint, sas)))
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
