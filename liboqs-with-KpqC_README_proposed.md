# liboqs-with-KpqC

`liboqs-with-KpqC` is a research-oriented fork of [Open Quantum Safe (OQS) liboqs](https://github.com/open-quantum-safe/liboqs) that adds the Korean Post-Quantum Cryptography (KpqC) algorithm families:

- **Digital signatures:** AIMer, HAETAE
- **Key encapsulation mechanisms (KEMs):** SMAUG/SMAUG-T, NTRU+

The purpose of this repository is to make the KpqC algorithms available through the common `liboqs` API so that they can be tested, benchmarked, and integrated into higher-level software such as OpenSSL 3 through [`oqs-provider-with-kpqc`](https://github.com/17seetwice/oqs-provider-with-kpqc).

> **Research/prototyping only.** This fork is intended for experimentation, interoperability testing, benchmarking, and academic research. Do not rely on it to protect production secrets without an appropriate security review.

---

## 1. How the two repositories fit together

```text
Application / TLS 1.3
        |
        v
OpenSSL 3.x
        |
        v
oqs-provider-with-kpqc
        |
        v
liboqs-with-KpqC
        |
        +-- AIMer
        +-- HAETAE
        +-- SMAUG / SMAUG-T
        +-- NTRU+
```

- **This repository (`liboqs-with-KpqC`)** contains the cryptographic implementations and the common liboqs API.
- **`oqs-provider-with-kpqc`** exposes the algorithms from this library to OpenSSL 3.x.
- If your goal is to run KpqC algorithms in TLS/X.509 with OpenSSL, install this repository first and then build the provider.

---

## 2. KpqC algorithms included

| Algorithm | Type | Main design basis | Suggested starting point |
|---|---|---|---|
| **AIMer** | Digital signature | Symmetric primitive / MPC-in-the-Head | [Official site](https://aimer-signature.org/) |
| **HAETAE** | Digital signature | Module lattices; Module-LWE/SIS; Fiat-Shamir with Aborts | [Official site](https://kpqc.cryptolab.co.kr/haetae) |
| **SMAUG / SMAUG-T** | KEM | Module-LWE + Module-LWR; Fujisaki-Okamoto transform | [Official site](https://kpqc.cryptolab.co.kr/smaug-t) |
| **NTRU+** | KEM | NTRU lattice construction with compact encoding | [Official site](https://www.ntruplus.org/) |

Official KpqC final algorithm documents:
- https://www.kpqc.or.kr/contents/03_exhibit/sub_03.html

> Note: the KpqC competition has published final specifications for AIMer, HAETAE, NTRU+, and SMAUG-T. Korean Standards (KS) standardization is a separate process and may continue to evolve. Check the official KpqC and algorithm websites for the newest specifications.

---

## 3. Verified build environment

| Component | Verified configuration |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Architecture | x86_64 |
| WSL | WSL2 is also supported for local development |
| Build system | CMake + Ninja |
| Compiler | GCC |
| Library type | Shared library (`BUILD_SHARED_LIBS=ON`) |
| Example install prefix | `/opt/liboqs-kpqc` |

This is a **verified environment**, not a strict minimum requirement.

---

## 4. Quick start — Ubuntu 24.04

### 4.1 Install build dependencies

```bash
sudo apt update
sudo apt install -y \
    git \
    cmake \
    ninja-build \
    build-essential \
    python3 \
    python3-pytest \
    python3-pytest-xdist
```

### 4.2 Clone this repository

```bash
git clone https://github.com/17seetwice/liboqs-with-KpqC.git
cd liboqs-with-KpqC
```

### 4.3 Configure

```bash
cmake -S . -B build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_INSTALL_PREFIX=/opt/liboqs-kpqc
```

### 4.4 Build

```bash
cmake --build build -j$(nproc)
```

### 4.5 Optional: run the liboqs test suite

```bash
ninja -C build run_tests
```

### 4.6 Install

```bash
sudo cmake --install build
```

### 4.7 Verify

```bash
ls -l /opt/liboqs-kpqc/lib/
find /opt/liboqs-kpqc -name "liboqsConfig.cmake"
```

A typical CMake package path is:

```text
/opt/liboqs-kpqc/lib/cmake/liboqs/liboqsConfig.cmake
```

---

## 5. Next step: use KpqC with OpenSSL 3

Continue with:
- https://github.com/17seetwice/oqs-provider-with-kpqc

The provider should be configured with:

```bash
-Dliboqs_DIR=/opt/liboqs-kpqc/lib/cmake/liboqs
```

For TLS 1.3 signature experiments, OpenSSL **3.2 or newer** is recommended. The verified setup for this fork uses **OpenSSL 3.4.4**.

---

## 6. Algorithm references and learning resources

### AIMer

**Start with:** MPC-in-the-Head signatures, symmetric-primitive-based PQ signatures, and the AIM one-way function.

- Official site: https://aimer-signature.org/
- KpqC technical document: https://aimer-signature.org/docs/AIMer-KpqC-Document.pdf
- Seongkwang Kim et al., *AIM: Symmetric Primitive for Shorter Signatures with Stronger Security*, Cryptology ePrint Archive 2022/1387: https://eprint.iacr.org/2022/1387
- Reference implementation: https://github.com/samsungsds-research-papers/AIMer

### HAETAE

**Start with:** Module-LWE/SIS, Fiat-Shamir with Aborts, rejection sampling, and lattice-based signatures.

- Official site: https://kpqc.cryptolab.co.kr/haetae
- KpqC technical document: https://www.kpqc.or.kr/images/pdf2/HAETAE.pdf
- Jung Hee Cheon et al., *HAETAE: Shorter Lattice-Based Fiat-Shamir Signatures*, IACR TCHES 2024(3), 25–75: https://doi.org/10.46586/tches.v2024.i3.25-75
- ePrint: https://eprint.iacr.org/2023/624
- Reference implementation: https://github.com/CryptoLabInc/HAETAE

### SMAUG / SMAUG-T

**Start with:** Module-LWE, Module-LWR, sparse secrets, PKE-to-KEM conversion, and the Fujisaki-Okamoto transform.

- Official site: https://kpqc.cryptolab.co.kr/smaug-t
- Original KpqC technical document: https://www.kpqc.or.kr/images/pdf/Smaug.pdf
- Jung Hee Cheon et al., *SMAUG(-T), Revisited: Timing-Secure, More Compact, Less Failure*, IEEE Access, 2024: https://doi.org/10.1109/ACCESS.2024.3511346
- Foundational SAC 2023 paper: https://doi.org/10.1007/978-3-031-53368-6_7
- Reference implementation: https://github.com/CryptoLabInc/SMAUG-T

### NTRU+

**Start with:** the NTRU problem, polynomial-ring lattices, encoding methods, and Fujisaki-Okamoto-style KEM transformations.

- Official site: https://www.ntruplus.org/
- KpqC technical specification: https://kpqc.or.kr/images/pdf2/NTRU%2B.pdf
- Jonghyun Kim, Jong Hwan Park, *NTRU+: Compact Construction of NTRU Using Simple Encoding Method*, IEEE TIFS 18, 4760–4774 (2023): https://doi.org/10.1109/TIFS.2023.3299172
- ePrint: https://eprint.iacr.org/2022/1664
- Reference implementation: https://github.com/ntruplus/ntruplus

---

## 7. Related publication

For broader background and comparison between NIST PQC and KpqC algorithms:

> 김명준, 서유진, 김영식, **“NIST PQC와 KpqC 알고리즘 비교 분석”**,  
> 2025년도 한국통신학회 하계종합학술발표회 논문집, pp. 1630–1631, June 2025.

- DBpia: https://www.dbpia.co.kr/journal/articleDetail?nodeId=NODE12361391

---

## 8. Upstream liboqs documentation

- Upstream liboqs: https://github.com/open-quantum-safe/liboqs
- Open Quantum Safe: https://openquantumsafe.org/

The upstream documentation remains applicable unless this fork explicitly documents a KpqC-specific difference.
