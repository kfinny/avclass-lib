from pkg_resources import get_distribution, DistributionNotFound
from .avclass import *
from .labeler import *

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound as e:
    __version__ = str(e)

__all__ = ("SampleInfo",
           "LabeledSample",
           "AvLabels",
           "Detector",
           "Labeler",
           "GroundTruth")

