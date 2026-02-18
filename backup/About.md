- Senior Software Developer & Researcher
- Projects I have participated in:
  - [DAS-Sandbox](https://sandbox.dbappsecurity.com.cn/)(Maleware Sandbox) - **UNIX-like Malware Research**, **Network Simulation Engine**
  - [DAS-AI](https://das-ai.com/)(AI for Cybersecurity) - **Code Execution Sandbox**, **LLM Gateway**
  - Hunter(DAST) - **Network Asset Discovery**, **DAST**, **WebApp Fingerprinting**

## Open Source Projects

- [Hyuga](https://github.com/ac0d3r/Hyuga)｜A tool for monitoring Out-of-Band (OOB) traffic, supporting DNS, HTTP, LDAP, RMI, and DNS-Rebinding. <img src="https://img.shields.io/github/stars/ac0d3r/Hyuga?logo=github" height="18">
- [xssfinder](https://github.com/ac0d3r/xssfinder)｜A tool for detecting DOM-Based XSS using taint analysis, based on Chrome Headless for dynamic semantic analysis of JavaScript. <img src="https://img.shields.io/github/stars/ac0d3r/xssfinder?logo=github" height="18">
- [TrollAppDuplicator](https://github.com/BreakOnCrash/TrollAppDuplicator) | iOS App duplicator for TrollStore <img src="https://img.shields.io/github/stars/BreakOnCrash/TrollAppDuplicator?logo=github" height="18">
- [go-embed-extractor](https://github.com/BreakOnCrash/go-embed-extractor)｜Extracting Go embeds <img src="https://img.shields.io/github/stars/BreakOnCrash/go-embed-extractor?logo=github" height="18">

### PR
- [Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard/pulls?q=is%3Apr+is%3Aclosed+author%3Aac0d3r) <img src="https://img.shields.io/github/stars/Tencent/AI-Infra-Guard?logo=github" height="18"> <a href="https://www.blackhat.com/eu-25/arsenal/schedule/index.html#aigai-infra-guard-48381" target="_blank"><img src="https://github.com/user-attachments/assets/2b86faa4-6efa-4269-a48d-91e46faeac21" height="30"></a>
  - Optimize the Fingerprint DSL parser (build AST and support short-circuit)
  - Fix out-of-bounds panic when quoted string ends with a backslash
  - Perf: reduce Docker image size
- [moonD4rk/HackBrowserData](https://github.com/moonD4rk/HackBrowserData/pulls?q=is%3Apr+author%3Aac0d3r+is%3Aclosed) <img src="https://img.shields.io/github/stars/moonD4rk/HackBrowserData?logo=github" height="18">
  - Decrypt the browser master key on macOS via gcore(CVE-2025-24204)
- [NSEcho/furlzz](https://github.com/NSEcho/furlzz/pulls?q=is%3Apr+is%3Aclosed+author%3Aac0d3r) <img src="https://img.shields.io/github/stars/NSEcho/furlzz?logo=github" height="18">
  - Add coverage guided with Stalker
  - fix(init): use passed-in type when creating config
- [Hemmelig.app](https://github.com/HemmeligOrg/Hemmelig.app/pulls?q=is%3Apr+is%3Aclosed+author%3Aac0d3r) <img src="https://img.shields.io/github/stars/HemmeligOrg/Hemmelig.app?logo=github" height="18">
  - Fix: Public secrets can be opened without a decryption key
  - Fix: toggle Editor between read-only and editable
- [saferwall/elf](https://github.com/saferwall/elf/pulls?q=is%3Apr+is%3Aclosed+author%3Aac0d3r) <img src="https://img.shields.io/github/stars/saferwall/elf?logo=github" height="18">
  - Fix parsing of ELF section header
- [boy-hack/hack-requests](https://github.com/boy-hack/hack-requests/pulls?q=is%3Apr+author%3Aac0d3r+is%3Aclosed) <img src="https://img.shields.io/github/stars/boy-hack/hack-requests?logo=github" height="18">

## Vulnerability Research
<table>
  <tr>
    <td><a href="https://huntr.com/bounties/921ba5d4-f1d0-4c66-9764-4f72dffe7acd">CVE-2025-1975</a></td>
    <td><a href="https://github.com/ollama/ollama">Ollama</a> <img src="https://img.shields.io/github/stars/ollama/ollama?logo=github" height="18"></td>
    <td>DoS</td>
  </tr>
  <tr>
    <td>CVE-2025-15453</td>
    <td><a href="https://github.com/milvus-io/milvus">milvus</a> <img src="https://img.shields.io/github/stars/milvus-io/milvus?logo=github" height="18"></td>
    <td>REE, (By 0x1f and ac0d3r)</td>
  </tr>
  <tr>
    <td>CVE-2025-14606</td>
    <td><a href="https://github.com/tiny-craft/tiny-rdm">Tiny RDM</a> <img src="https://img.shields.io/github/stars/tiny-craft/tiny-rdm?logo=github" height="18"></td>
    <td>Insecure Deserialization, RCE</td>
  </tr>
  <tr>
    <td>CVE-2025-5030<br>CVE-2025-5031</td>
    <td><a href="https://github.com/Ackites/KillWxapkg">KillWxapkg</a> <img src="https://img.shields.io/github/stars/Ackites/KillWxapkg?logo=github" height="18"></td>
    <td>Arbitrary File Write, RCE<br>DoS</td>
  </tr>
  <tr>
    <td><a href="https://github.com/advisories/GHSA-6556-fwc2-fg2p">GHSA-6556-fwc2-fg2p</a><br>
    <a href="https://github.com/advisories/GHSA-rrxm-2pvv-m66x">GHSA-rrxm-2pvv-m66x</a><br></td>
    <td><a href="https://github.com/mmaitre314/picklescan">picklescan</a> <img src="https://img.shields.io/github/stars/mmaitre314/picklescan?logo=github" height="18"></td>
    <td>Pickle deserialization detection bypass</td>
  </tr>
  <tr>
    <td>CVE-2025-10975</td>
    <td><a href="https://github.com/GuanxingLu/vlarl">vlarl</a> <img src="https://img.shields.io/github/stars/GuanxingLu/vlarl?logo=github" height="18"></td>
    <td>Insecure Deserialization, RCE</td>
  </tr>
  <tr>
    <td>CVE-2025-8729</td>
    <td><a href="https://github.com/MigoXLab/LMeterX">LMeterX</a> <img src="https://img.shields.io/github/stars/MigoXLab/LMeterX?logo=github" height="18"></td>
    <td>Path Traversal</td>
  </tr>
  <tr>
    <td>CVE-2025-10974</td>
    <td><a href="https://github.com/giantspatula/SewKinect">SewKinect</a> <img src="https://img.shields.io/github/stars/giantspatula/SewKinect?logo=github" height="18"></td>
    <td>Insecure Deserialization, RCE</td>
  </tr>
  <tr>
    <td>CVE-2024-2007</td>
    <td><a href="https://github.com/OpenBMB/XAgent">XAgent</a> <img src="https://img.shields.io/github/stars/OpenBMB/XAgent?logo=github" height="18"></td>
    <td>Container Escape</td>
  </tr>
  <tr>
    <td><a href="https://tttang.com/archive/1904/">CVE-2023-34655</a></td>
    <td>ClashX</td>
    <td>Unauthorized XPC Access Allows System Proxy Tampering</td>
  </tr>
  <tr>
    <td>N/A/Oct 5, 2022</td>
    <td>Clash</td>
    <td>In-the-wild 0-day 1click-RCE</td>
  </tr>
</table>

## Toy program
- [fbuzzer](https://github.com/BreakOnCrash/fbuzzer) | A Frida-based toy in-process fuzzer 📣
- [inx](https://github.com/BreakOnCrash/inx)｜Inject *.dylib into target process (like Frida) on macOS (arm64 and x86_64) 💉
- [go-symbolic-execution](https://github.com/BreakOnCrash/go-symbolic-execution) | Go white-box symbolic execution demo 👨🏻‍💻
- [TrollR2ool](https://github.com/BreakOnCrash/TrollR2ool) | iOS Runtime analysis tool 🧌
---
- [gf.imipy.com](https://gf.imipy.com/) - Today's meal picker 🥣
- [pinger](https://github.com/ac0d3r/pingser) - Transfer custom messages via `ICMP`.
- [v2hreo](https://github.com/ac0d3r/v2hreo) - V2ray macOS Menu Bar Application with <img src="https://img.shields.io/badge/-292e33?logo=swift" height="18"> + CGO.
- [webportscan](https://github.com/ac0d3r/webportscan) - Scan local service (TCP) ports over Web page.
- [PiMonitor](https://github.com/ac0d3r/PiMonitor) - Build a Controllable Web Video Monitor with <img src="https://img.shields.io/badge/-292e33?logo=go" height="18">+<img src="https://img.shields.io/badge/4b-292e33?logo=raspberry-pi" height="18">.
- [Rua](https://github.com/ac0d3r/nicu?tab=readme-ov-file#rua) - Generate a <img src="https://user-images.githubusercontent.com/26270009/149051761-21e0e181-534d-458a-ad63-5c8963eda447.gif" height="30">(rua.gif) from any avatar.

## Others
- 微信公众号

<img src="https://github.com/user-attachments/assets/049439af-4a86-4106-abad-b438b21175d5" width=280>

- [Old Blog(CN)](https://ac0d3r.notion.site/zznQ-4b2780d3bf864ab3bee6044612f6e631)
