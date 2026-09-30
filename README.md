# 🛡 Omni Audit 

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Powered by Omni Line](https://img.shields.io/badge/Powered%20by-Omni%20Line-FF4B4B?style=flat)](https://omniline.app/)

**Omni Audit** is a blazing-fast, zero-dependency CLI tool that scans your codebase for **Dependency Confusion** risks. It automatically detects your package manager and checks if your internal/private packages are vulnerable to being hijacked by public registries.

## ⚠️ The Problem: Dependency Confusion
If your company uses both a private registry and a public one (like NPM or Packagist), your build system might accidentally download a malicious public package that shares the same name as your private internal package. This supply chain attack has compromised major tech companies in recent years.

**Omni Audit** catches this *before* it happens.

## ✨ Features
* **Zero Config:** Just run it. It auto-detects your package manager.
* **Blazing Fast:** Written in Go, it scans hundreds of dependencies in milliseconds.
* **CI/CD Ready:** Returns exit code `1` if vulnerabilities are found, failing the pipeline immediately to protect your build.
* **No Dependencies:** Distributed as a standalone binary.

---

<div align="center">
  <a href="https://omniline.app/">
    <img src="https://omniline.app/omni-line-icon.png" alt="Omni Line - Enterprise Supply Chain Security" width="150" style="margin-bottom: 20px;">
  </a>

  <h2>🛡️ Enterprise Supply Chain Security</h2>
  <p>
    <b>Omni Audit</b> is proudly built and maintained by the team at <a href="https://omniline.app/"><b>Omni Line</b></a>.
  </p>
  <p>
    Auditing is only the first step. If your team manages multiple package managers and relies on a mix of private and public dependencies, keeping configuration files secure across dozens of developers and CI pipelines is a major security risk.
  </p>
  <p>
    <b>Omni Line</b> solves this permanently by acting as an intelligent gateway for your software supply chain:
  </p>
  
  <p>
    ✅ <b>Smart Routing:</b> Guarantees internal packages are never fetched from public registries.<br>
    ✅ <b>Unified Access:</b> Manage all your registries (NPM, PHP, etc.) from a single control plane.<br>
    ✅ <b>High Availability:</b> Cache dependencies to keep your CI/CD fast and resilient against public outages.
  </p>
  <br>
</div>
