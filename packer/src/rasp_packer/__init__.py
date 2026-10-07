"""The RASP packer: adds the runtime to a built Android or iOS app.

The packer is a library. `rasp_packer.packer.pack` is its entry point, and the `rasp` command line
is a thin client of it. The packer returns the app unsigned: the customer signs it.
"""
