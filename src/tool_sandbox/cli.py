"""Command-line interface for tool-sandbox."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .checker import check_plan, load_plan, load_policy
