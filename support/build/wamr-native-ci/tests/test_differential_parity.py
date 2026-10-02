# SPDX-License-Identifier: BSD-3-Clause
"""Compatibility import for downstream neutral fixtures, not a live harness.

The local/full Python-versus-native runner has been retired. #187/#189 should
import controller_record_fixtures directly; this name remains during rebases.
"""
from controller_record_fixtures import (  # noqa: F401
    FIXTURES, MODES, RecordFixtures as DeterministicContracts,
    accepted_result, write_result_fixture,
)


if __name__ == "__main__":
    import sys
    print("Controller differential CLI retired; use native qualification gates.",
          file=sys.stderr)
    sys.exit(2)
