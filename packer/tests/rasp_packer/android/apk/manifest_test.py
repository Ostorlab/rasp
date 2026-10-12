"""Tests of the manifest semantic layer."""

import pathlib

from rasp_packer.android.apk import manifest

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def testApplicationClass_whenDeclared_returnsIt() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()
    assert manifest.application_class(data) == "com.example.withapp.MyApp"


def testApplicationClass_whenAbsent_returnsDefault() -> None:
    data = (_FIXTURES / "manifest_without_application.bin").read_bytes()
    assert manifest.application_class(data) == manifest.DEFAULT_APPLICATION_CLASS


def testSetApplicationClass_whenAbsent_setsTheName() -> None:
    data = (_FIXTURES / "manifest_without_application.bin").read_bytes()
    edited = manifest.set_application_class(data, "co.ostorlab.rasp.RaspStub")
    assert manifest.application_class(edited) == "co.ostorlab.rasp.RaspStub"


def testApplicationClass_whenRelativeDottedName_prependsThePackage() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()
    edited = manifest.set_application_class(data, ".MyApp")
    assert manifest.application_class(edited) == "com.example.withapp.MyApp"


def testApplicationClass_whenBareName_prependsThePackage() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()
    edited = manifest.set_application_class(data, "MyApp")
    assert manifest.application_class(edited) == "com.example.withapp.MyApp"


def testApplicationClass_whenFullyQualifiedName_returnsItUnchanged() -> None:
    data = (_FIXTURES / "manifest_with_application.bin").read_bytes()
    edited = manifest.set_application_class(data, "com.other.MyApp")
    assert manifest.application_class(edited) == "com.other.MyApp"
