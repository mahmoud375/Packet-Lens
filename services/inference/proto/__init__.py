# PacketLens Protobuf Exports
# Auto-generated stubs from proto/packetlens.proto
#
# Usage:
#   from services.inference.proto import FeatureVector, Verdict, InferenceServiceServicer

from .packetlens_pb2 import (
    FeatureVector,
    Verdict,
)

from .packetlens_pb2_grpc import (
    InferenceServiceServicer,
    InferenceServiceStub,
    add_InferenceServiceServicer_to_server,
)

__all__ = [
    # Messages
    "FeatureVector",
    "Verdict",
    # Service classes
    "InferenceServiceServicer",
    "InferenceServiceStub",
    "add_InferenceServiceServicer_to_server",
]
