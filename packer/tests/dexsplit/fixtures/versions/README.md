# Genuine DEX version features

Regenerate with `build/dexsplit-host/dexsplit_fixtures tests/dexsplit/fixtures/versions`
after building the native CMake test target. Source is `dexsplit/tests/feature_fixture.hpp`.
035 includes fields, constants, annotations and debug information; 037 adds an interface
default method; 038 uses invoke-polymorphic; 039 uses const-method-type; 040 uses spaces
in class/member names. `unicode-039.dex` has a supplementary Unicode class name.
These small source-generated format fixtures are not claimed ART-verifiable programs.

`python tests/dexsplit/fixtures/validate.py tests/dexsplit/fixtures/versions --dexdump /path/to/SDK35/dexdump`
checks all digests/layouts independently and requires real SDK checksum/disassembly checks.
The separately built SDK D8/R8 app in `../app/` provides the runnable ART fixture.
