#!/bin/bash
set -e

EXPECTED_CLASS_HASH="0x00123e6bc1c14ae9934e933d3f64916a6116dd6b036a922b2b1f0815e0d1d300"

# Build with release profile
echo "Building with release profile..."
SCARB_PROFILE=release scarb build

# Compute class hash using sncast (extract just the hash from output)
echo "Computing Primer class hash..."
SNCAST_OUTPUT=$(sncast utils class-hash --package contracts --contract-name Primer 2>&1)
ACTUAL_CLASS_HASH=$(echo "$SNCAST_OUTPUT" | grep "Class Hash:" | awk '{print $3}')

# Compare
echo "Expected: $EXPECTED_CLASS_HASH"
echo "Actual:   $ACTUAL_CLASS_HASH"

if [ "$ACTUAL_CLASS_HASH" = "$EXPECTED_CLASS_HASH" ]; then
    echo "SUCCESS: Primer class hash matches expected value"
    exit 0
else
    echo "FAILURE: Primer class hash mismatch!"
    exit 1
fi
