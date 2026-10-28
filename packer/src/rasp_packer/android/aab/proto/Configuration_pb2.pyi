from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Configuration(_message.Message):
    __slots__ = ["density", "hdr", "keyboard", "keys_hidden", "layout_direction", "locale", "mcc", "mnc", "nav_hidden", "navigation", "orientation", "product", "screen_height", "screen_height_dp", "screen_layout_long", "screen_layout_size", "screen_round", "screen_width", "screen_width_dp", "sdk_version", "smallest_screen_width_dp", "touchscreen", "ui_mode_night", "ui_mode_type", "wide_color_gamut"]
    class Hdr(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Keyboard(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class KeysHidden(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class LayoutDirection(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class NavHidden(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Navigation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Orientation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class ScreenLayoutLong(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class ScreenLayoutSize(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class ScreenRound(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Touchscreen(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class UiModeNight(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class UiModeType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class WideColorGamut(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    DENSITY_FIELD_NUMBER: _ClassVar[int]
    HDR_FIELD_NUMBER: _ClassVar[int]
    HDR_HIGHDR: Configuration.Hdr
    HDR_LOWDR: Configuration.Hdr
    HDR_UNSET: Configuration.Hdr
    KEYBOARD_FIELD_NUMBER: _ClassVar[int]
    KEYBOARD_NOKEYS: Configuration.Keyboard
    KEYBOARD_QWERTY: Configuration.Keyboard
    KEYBOARD_TWELVEKEY: Configuration.Keyboard
    KEYBOARD_UNSET: Configuration.Keyboard
    KEYS_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    KEYS_HIDDEN_KEYSEXPOSED: Configuration.KeysHidden
    KEYS_HIDDEN_KEYSHIDDEN: Configuration.KeysHidden
    KEYS_HIDDEN_KEYSSOFT: Configuration.KeysHidden
    KEYS_HIDDEN_UNSET: Configuration.KeysHidden
    LAYOUT_DIRECTION_FIELD_NUMBER: _ClassVar[int]
    LAYOUT_DIRECTION_LTR: Configuration.LayoutDirection
    LAYOUT_DIRECTION_RTL: Configuration.LayoutDirection
    LAYOUT_DIRECTION_UNSET: Configuration.LayoutDirection
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    MCC_FIELD_NUMBER: _ClassVar[int]
    MNC_FIELD_NUMBER: _ClassVar[int]
    NAVIGATION_DPAD: Configuration.Navigation
    NAVIGATION_FIELD_NUMBER: _ClassVar[int]
    NAVIGATION_NONAV: Configuration.Navigation
    NAVIGATION_TRACKBALL: Configuration.Navigation
    NAVIGATION_UNSET: Configuration.Navigation
    NAVIGATION_WHEEL: Configuration.Navigation
    NAV_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    NAV_HIDDEN_NAVEXPOSED: Configuration.NavHidden
    NAV_HIDDEN_NAVHIDDEN: Configuration.NavHidden
    NAV_HIDDEN_UNSET: Configuration.NavHidden
    ORIENTATION_FIELD_NUMBER: _ClassVar[int]
    ORIENTATION_LAND: Configuration.Orientation
    ORIENTATION_PORT: Configuration.Orientation
    ORIENTATION_SQUARE: Configuration.Orientation
    ORIENTATION_UNSET: Configuration.Orientation
    PRODUCT_FIELD_NUMBER: _ClassVar[int]
    SCREEN_HEIGHT_DP_FIELD_NUMBER: _ClassVar[int]
    SCREEN_HEIGHT_FIELD_NUMBER: _ClassVar[int]
    SCREEN_LAYOUT_LONG_FIELD_NUMBER: _ClassVar[int]
    SCREEN_LAYOUT_LONG_LONG: Configuration.ScreenLayoutLong
    SCREEN_LAYOUT_LONG_NOTLONG: Configuration.ScreenLayoutLong
    SCREEN_LAYOUT_LONG_UNSET: Configuration.ScreenLayoutLong
    SCREEN_LAYOUT_SIZE_FIELD_NUMBER: _ClassVar[int]
    SCREEN_LAYOUT_SIZE_LARGE: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_NORMAL: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_SMALL: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_UNSET: Configuration.ScreenLayoutSize
    SCREEN_LAYOUT_SIZE_XLARGE: Configuration.ScreenLayoutSize
    SCREEN_ROUND_FIELD_NUMBER: _ClassVar[int]
    SCREEN_ROUND_NOTROUND: Configuration.ScreenRound
    SCREEN_ROUND_ROUND: Configuration.ScreenRound
    SCREEN_ROUND_UNSET: Configuration.ScreenRound
    SCREEN_WIDTH_DP_FIELD_NUMBER: _ClassVar[int]
    SCREEN_WIDTH_FIELD_NUMBER: _ClassVar[int]
    SDK_VERSION_FIELD_NUMBER: _ClassVar[int]
    SMALLEST_SCREEN_WIDTH_DP_FIELD_NUMBER: _ClassVar[int]
    TOUCHSCREEN_FIELD_NUMBER: _ClassVar[int]
    TOUCHSCREEN_FINGER: Configuration.Touchscreen
    TOUCHSCREEN_NOTOUCH: Configuration.Touchscreen
    TOUCHSCREEN_STYLUS: Configuration.Touchscreen
    TOUCHSCREEN_UNSET: Configuration.Touchscreen
    UI_MODE_NIGHT_FIELD_NUMBER: _ClassVar[int]
    UI_MODE_NIGHT_NIGHT: Configuration.UiModeNight
    UI_MODE_NIGHT_NOTNIGHT: Configuration.UiModeNight
    UI_MODE_NIGHT_UNSET: Configuration.UiModeNight
    UI_MODE_TYPE_APPLIANCE: Configuration.UiModeType
    UI_MODE_TYPE_CAR: Configuration.UiModeType
    UI_MODE_TYPE_DESK: Configuration.UiModeType
    UI_MODE_TYPE_FIELD_NUMBER: _ClassVar[int]
    UI_MODE_TYPE_NORMAL: Configuration.UiModeType
    UI_MODE_TYPE_TELEVISION: Configuration.UiModeType
    UI_MODE_TYPE_UNSET: Configuration.UiModeType
    UI_MODE_TYPE_VRHEADSET: Configuration.UiModeType
    UI_MODE_TYPE_WATCH: Configuration.UiModeType
    WIDE_COLOR_GAMUT_FIELD_NUMBER: _ClassVar[int]
    WIDE_COLOR_GAMUT_NOWIDECG: Configuration.WideColorGamut
    WIDE_COLOR_GAMUT_UNSET: Configuration.WideColorGamut
    WIDE_COLOR_GAMUT_WIDECG: Configuration.WideColorGamut
    density: int
    hdr: Configuration.Hdr
    keyboard: Configuration.Keyboard
    keys_hidden: Configuration.KeysHidden
    layout_direction: Configuration.LayoutDirection
    locale: str
    mcc: int
    mnc: int
    nav_hidden: Configuration.NavHidden
    navigation: Configuration.Navigation
    orientation: Configuration.Orientation
    product: str
    screen_height: int
    screen_height_dp: int
    screen_layout_long: Configuration.ScreenLayoutLong
    screen_layout_size: Configuration.ScreenLayoutSize
    screen_round: Configuration.ScreenRound
    screen_width: int
    screen_width_dp: int
    sdk_version: int
    smallest_screen_width_dp: int
    touchscreen: Configuration.Touchscreen
    ui_mode_night: Configuration.UiModeNight
    ui_mode_type: Configuration.UiModeType
    wide_color_gamut: Configuration.WideColorGamut
    def __init__(self, mcc: _Optional[int] = ..., mnc: _Optional[int] = ..., locale: _Optional[str] = ..., layout_direction: _Optional[_Union[Configuration.LayoutDirection, str]] = ..., screen_width: _Optional[int] = ..., screen_height: _Optional[int] = ..., screen_width_dp: _Optional[int] = ..., screen_height_dp: _Optional[int] = ..., smallest_screen_width_dp: _Optional[int] = ..., screen_layout_size: _Optional[_Union[Configuration.ScreenLayoutSize, str]] = ..., screen_layout_long: _Optional[_Union[Configuration.ScreenLayoutLong, str]] = ..., screen_round: _Optional[_Union[Configuration.ScreenRound, str]] = ..., wide_color_gamut: _Optional[_Union[Configuration.WideColorGamut, str]] = ..., hdr: _Optional[_Union[Configuration.Hdr, str]] = ..., orientation: _Optional[_Union[Configuration.Orientation, str]] = ..., ui_mode_type: _Optional[_Union[Configuration.UiModeType, str]] = ..., ui_mode_night: _Optional[_Union[Configuration.UiModeNight, str]] = ..., density: _Optional[int] = ..., touchscreen: _Optional[_Union[Configuration.Touchscreen, str]] = ..., keys_hidden: _Optional[_Union[Configuration.KeysHidden, str]] = ..., keyboard: _Optional[_Union[Configuration.Keyboard, str]] = ..., nav_hidden: _Optional[_Union[Configuration.NavHidden, str]] = ..., navigation: _Optional[_Union[Configuration.Navigation, str]] = ..., sdk_version: _Optional[int] = ..., product: _Optional[str] = ...) -> None: ...
