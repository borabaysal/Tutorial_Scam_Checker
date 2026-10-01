"""Tutorial Scam Checker: does this 'AI trading bot' trade, or just forward your funds?"""

from .checker import check
from .solidity import analyze_solidity
from .verdict import compute_verdict

__all__ = ["check", "analyze_solidity", "compute_verdict"]
__version__ = "0.1.0"
