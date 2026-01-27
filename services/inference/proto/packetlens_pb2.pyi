from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class FeatureVector(_message.Message):
    __slots__ = ("flow_id", "features", "timestamp_ns")
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    flow_id: str
    features: _containers.RepeatedScalarFieldContainer[float]
    timestamp_ns: int
    def __init__(self, flow_id: _Optional[str] = ..., features: _Optional[_Iterable[float]] = ..., timestamp_ns: _Optional[int] = ...) -> None: ...

class Verdict(_message.Message):
    __slots__ = ("flow_id", "label", "confidence", "inference_time_us")
    FLOW_ID_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    INFERENCE_TIME_US_FIELD_NUMBER: _ClassVar[int]
    flow_id: str
    label: str
    confidence: float
    inference_time_us: int
    def __init__(self, flow_id: _Optional[str] = ..., label: _Optional[str] = ..., confidence: _Optional[float] = ..., inference_time_us: _Optional[int] = ...) -> None: ...
