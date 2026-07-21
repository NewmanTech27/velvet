"""velvet.tools — auxiliary companion tools (spec/printers-and-tools.md §B).

Each tool is a separate console entry point reusing the analyzer pipeline:

- :mod:`velvet.tools.check_erc` — ERC-20/721/1155 conformance checker
  (``velvet-check-erc``).
- :mod:`velvet.tools.flat` — source flattener (``velvet-flat``).
- :mod:`velvet.tools.interface` — interface generator (``velvet-interface``).

Original clean-room implementation.
"""
