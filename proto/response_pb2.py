# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: response.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='response.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0eresponse.proto\"\xc5\x02\n\x08Response\x12%\n\x05wifis\x18\x02 \x03(\x0b\x32\x16.Response.ResponseWifi\x1a\x91\x02\n\x0cResponseWifi\x12\x0b\n\x03mac\x18\x01 \x01(\t\x12\x35\n\x08location\x18\x02 \x01(\x0b\x32#.Response.ResponseWifi.WifiLocation\x12\x0f\n\x07\x63hannel\x18\x15 \x01(\x05\x1a\xab\x01\n\x0cWifiLocation\x12\x10\n\x08latitude\x18\x01 \x01(\x03\x12\x11\n\tlongitude\x18\x02 \x01(\x03\x12\x10\n\x08\x61\x63\x63uracy\x18\x03 \x01(\x05\x12\x12\n\nzeroField4\x18\x04 \x01(\x05\x12\x10\n\x08\x61ltitude\x18\x05 \x01(\x05\x12\x18\n\x10\x61ltitudeAccuracy\x18\x06 \x01(\x05\x12\x11\n\tunknown11\x18\x0b \x01(\x05\x12\x11\n\tunknown12\x18\x0c \x01(\x05'
)




_RESPONSE_RESPONSEWIFI_WIFILOCATION = _descriptor.Descriptor(
  name='WifiLocation',
  full_name='Response.ResponseWifi.WifiLocation',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='latitude', full_name='Response.ResponseWifi.WifiLocation.latitude', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='longitude', full_name='Response.ResponseWifi.WifiLocation.longitude', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accuracy', full_name='Response.ResponseWifi.WifiLocation.accuracy', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='zeroField4', full_name='Response.ResponseWifi.WifiLocation.zeroField4', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='altitude', full_name='Response.ResponseWifi.WifiLocation.altitude', index=4,
      number=5, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='altitudeAccuracy', full_name='Response.ResponseWifi.WifiLocation.altitudeAccuracy', index=5,
      number=6, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='unknown11', full_name='Response.ResponseWifi.WifiLocation.unknown11', index=6,
      number=11, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='unknown12', full_name='Response.ResponseWifi.WifiLocation.unknown12', index=7,
      number=12, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=173,
  serialized_end=344,
)

_RESPONSE_RESPONSEWIFI = _descriptor.Descriptor(
  name='ResponseWifi',
  full_name='Response.ResponseWifi',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='mac', full_name='Response.ResponseWifi.mac', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='location', full_name='Response.ResponseWifi.location', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='channel', full_name='Response.ResponseWifi.channel', index=2,
      number=21, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_RESPONSE_RESPONSEWIFI_WIFILOCATION, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=71,
  serialized_end=344,
)

_RESPONSE = _descriptor.Descriptor(
  name='Response',
  full_name='Response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='wifis', full_name='Response.wifis', index=0,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_RESPONSE_RESPONSEWIFI, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=19,
  serialized_end=344,
)

_RESPONSE_RESPONSEWIFI_WIFILOCATION.containing_type = _RESPONSE_RESPONSEWIFI
_RESPONSE_RESPONSEWIFI.fields_by_name['location'].message_type = _RESPONSE_RESPONSEWIFI_WIFILOCATION
_RESPONSE_RESPONSEWIFI.containing_type = _RESPONSE
_RESPONSE.fields_by_name['wifis'].message_type = _RESPONSE_RESPONSEWIFI
DESCRIPTOR.message_types_by_name['Response'] = _RESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), {

  'ResponseWifi' : _reflection.GeneratedProtocolMessageType('ResponseWifi', (_message.Message,), {

    'WifiLocation' : _reflection.GeneratedProtocolMessageType('WifiLocation', (_message.Message,), {
      'DESCRIPTOR' : _RESPONSE_RESPONSEWIFI_WIFILOCATION,
      '__module__' : 'response_pb2'
      # @@protoc_insertion_point(class_scope:Response.ResponseWifi.WifiLocation)
      })
    ,
    'DESCRIPTOR' : _RESPONSE_RESPONSEWIFI,
    '__module__' : 'response_pb2'
    # @@protoc_insertion_point(class_scope:Response.ResponseWifi)
    })
  ,
  'DESCRIPTOR' : _RESPONSE,
  '__module__' : 'response_pb2'
  # @@protoc_insertion_point(class_scope:Response)
  })
_sym_db.RegisterMessage(Response)
_sym_db.RegisterMessage(Response.ResponseWifi)
_sym_db.RegisterMessage(Response.ResponseWifi.WifiLocation)


# @@protoc_insertion_point(module_scope)
