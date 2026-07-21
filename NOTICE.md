# Clean-Room Provenance Notice

Velvet is an original, independently developed static analysis framework for
EVM smart contracts, licensed under the Apache License 2.0.

## Relationship to other tools

Velvet provides functionality comparable to Trail of Bits' Slither. Slither is
licensed under the GNU Affero General Public License v3 (AGPLv3). **No part of
Slither's source code was read, copied, adapted, or paraphrased in the creation
of Velvet.**

## Clean-room process

Velvet was produced with a two-team clean-room process:

1. **Specification team** — derived neutral functional specifications
   exclusively from *publicly available documentation*: the reference tool's
   README and public wiki, the peer-reviewed WETSEB'19 paper
   (*"Slither: A Static Analysis Framework For Smart Contracts"*,
   arXiv:1908.09878), public EIP standards (EIP-20/721/1155), the SWC registry,
   and general static-analysis literature. The resulting specifications
   (retained in `spec/`) describe *what* each feature does, never *how* any
   existing implementation does it, and cite their public sources.
2. **Implementation team** — implemented Velvet solely from those
   specifications, without access to the reference tool's source code. All
   source code, example contracts, fixtures, and tests in this repository are
   original works of the Velvet contributors.

Velvet's architecture, naming, APIs, and implementation choices are its own.
Detector identifiers follow industry-wide naming conventions for vulnerability
classes (e.g. "reentrancy-eth") for ecosystem compatibility; the underlying
detection logic is independently implemented.

If you believe any material in this repository violates these principles,
please open an issue and it will be investigated and remediated promptly.
