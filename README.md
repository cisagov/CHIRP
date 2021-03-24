#

<div align="center">
<p align="center">
  <a href="" rel="noopener">
 <img width=200px height=200px src="assets/CISA_Logo.png" alt="CISA logo"></a>
</p>

<h3 align="center">CHIRP</h3>

[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![GitHub Issues](https://img.shields.io/github/issues/cisagov/chirp.svg)](https://github.com/cisagov/chirp/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/cisagov/chirp.svg)](https://github.com/cisagov/chirp/pulls)
[![License](https://img.shields.io/badge/license-CC0_1.0-blue.svg)](/LICENSE)

---

<p align="center"> A forensic collection tool written in Python.
    <br>
</p>
<p align="center"> Watch the <a href="https://www.youtube.com/watch?v=UGYSNiNOpds">video overview</a></p>
</div>

## 📝 Table of Contents

- [📝 Table of Contents](#-table-of-contents-)
- [🧐 About](#-about)
- [🏁 Getting Started](#-getting-started-)
  - [Prerequisites](#prerequisites)
  - [Installing](#installing)
- [🎈 Usage](#-usage-)
- [⛏️ Built Using](#️-built-using-)
- [✍️ Authors](#️-authors-)
- [🎉 Acknowledgements](#-acknowledgements-)
- [🤝 Contributing](#-contributing-)
- [📝 License](#-license-)
- [⚖️ Legal Disclaimer](#️-legal-disclaimer-)

## 🧐 About

The CISA Hunt and Incident Response Program (CHIRP) is a tool created to
dynamically query Indicators of Compromise (IoCs) on hosts with a single
package, outputting data in a JSON format for further analysis in a SIEM
or other tool. CHIRP does not modify any system data.

The initial IoCs are intended to search for activity
detailed in CISA Alert [AA21-008A](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
that has spilled into the enterprise environment.

## 🏁 Getting Started <a name = "getting_started"></a>

We build and release CHIRP via
[`Releases`](https://github.com/cisagov/chirp/releases).
However, if you wish to run with Python3.6+, follow these instructions.

You can also write new
[indicators](https://github.com/cisagov/CHIRP/blob/main/indicators/README.md)
or [plugins](https://github.com/cisagov/CHIRP/blob/main/chirp/plugins/README.md)
for CHIRP.

### Prerequisites

Python 3.6 or greater is required to run CHIRP with Python. If you need help
installing Python in your environment, follow the instructions
[here](https://docs.Python.org/3/using/windows.html)

CHIRP must be run on a live machine, but it does not have to be network connected.
Currently, CHIRP must run on the drive containing winevt logs.  Shortly after release,
this will be updated so CHIRP can run from any drive.

### Installing

```console
python3 -m pip install -e .
```

> In our experience, yara-python comes with some other dependencies. You MAY have
to install Visual Studio C++ 14.0 and the Windows 10 SDK, this can be retrieved
with [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/)

## 🎈 Usage <a name="usage"></a>

### From [release](https://github.com/cisagov/chirp/releases)

```console
# defaults
.\chirp.exe

# with args
.\chirp.exe -p registry -o chirp_result -l debug
```

### From python

```console
# defaults
python3 chirp.py

# with args
python3 chirp.py -p registry -o chirp_result -l debug
```

### Example output

```console
[15:32:19] [YARA] Enumerating the entire filesystem due to ['CISA Solar Fire', 'CISA Teardrop', 'CrowdStrike Rempack', 'CrowdStrike Sunspot', 'FireEye       common.py:103
           Cosmic Gale', 'FireEye Sunburst']... this is going to take a while.
           [YARA] Entered yara plugin.                                                                                                                       common.py:103
           [REGISTRY] Found 0 hit(s) for IFEO Persistence indicator.                                                                                         common.py:103
           [REGISTRY] Found 0 hit(s) for Teardrop - Registry Activity indicator.                                                                             common.py:103
           [REGISTRY] Found 0 hit(s) for Sibot - Registry indicator.
           ...
           ...
           ...
           [+] Done! Your results can be found at Z:\README\output.
```

## ⛏️ Built Using <a name = "built_using"></a>

- [Python](https://www.Python.org/) - Language
- [Nuitka](https://nuitka.net/) - For compilation
- [evtx2json](https://github.com/vavarachen/evtx2json) - For event log access
- [yara-python](https://github.com/VirusTotal/yara-python) - Parses and runs yara
rules
- [rich](https://github.com/willmcgugan/rich) - Makes the CLI easier on the eyes
- [psutil](https://github.com/giampaolo/psutil) - Provides an easy API for many
OS functions

## ✍️ Authors <a name = "authors"></a>

- [Will Deem, OS1 USCG](https://github.com/deemonsecurity)
- [Jordan Mussman](https://github.com/jklm264)

## 🎉 Acknowledgements <a name = "acknowledgement"></a>

- Denise Keating
- Liana Parakesyan
- Richard Kenny
- Megan Nadeau
- Ewa Dadok
- David Zito
- Chris Brown
- [Julian Blanco, LTJG USCG](https://github.com/julianblanco)
- [Caleb Stewart, LT USCG](https://github.com/calebstewart)

## 🤝 Contributing <a name = "contributing"></a>

We welcome contributions!  Please see [here](CONTRIBUTING.md) for details.

## 📝 License <a name = "license"></a>

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and copyright and
related rights in the work worldwide are waived through the
[CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0 dedication. By
submitting a pull request, you are agreeing to comply with this waiver of
copyright interest.

## ⚖️ Legal Disclaimer <a name = "legal_disclaimer"></a>

NOTICE

This software package (“software” or “code”) was created by the United States
Government and is not subject to copyright within the United States. All other
rights are reserved.  You may use, modify, or redistribute
the code in any manner. However, you may not subsequently copyright the code as
it is distributed. The United States Government makes no claim of copyright on
the changes you effect, nor will it restrict your distribution of bona fide
changes to the software. If you decide to update or redistribute the code, please
include this notice with the code. Where relevant, we ask that you credit the
Cybersecurity and Infrastructure Security Agency with the following statement:
“Original code developed by the Cybersecurity and Infrastructure Security Agency
(CISA), U.S. Department of Homeland Security.”

USE THIS SOFTWARE AT YOUR OWN RISK. THIS SOFTWARE COMES WITH NO WARRANTY, EITHER
EXPRESS OR IMPLIED. THE UNITED STATES GOVERNMENT ASSUMES NO LIABILITY FOR THE
USE OR MISUSE OF THIS SOFTWARE OR ITS DERIVATIVES.

THIS SOFTWARE IS OFFERED “AS-IS.” THE UNITED STATES GOVERNMENT WILL NOT INSTALL,
REMOVE, OPERATE OR SUPPORT THIS SOFTWARE AT YOUR REQUEST. IF YOU ARE UNSURE OF
HOW THIS SOFTWARE WILL INTERACT WITH YOUR SYSTEM, DO NOT USE IT.
