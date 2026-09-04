#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.

import os
import shlex
import subprocess


def configured_tool(variable, default):
    command = shlex.split(os.environ.get(variable, default))
    if not command:
        raise ValueError(f"{variable} tool command must not be empty")
    return command


def tool_output(command, *args, **kwargs):
    return subprocess.check_output([*command, *args], **kwargs)  # nosec
