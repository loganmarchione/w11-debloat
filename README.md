# w11-debloat

[![Lint PowerShell](https://github.com/loganmarchione/w11-debloat/actions/workflows/main.yml/badge.svg)](https://github.com/loganmarchione/w11-debloat/actions/workflows/main.yml)

## Explanation

A first-pass at de-bloating Windows 11

## Requirements

1. Open PowerShell as an administrator
2. Copy/paste the command below

```
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/loganmarchione/w11-debloat/refs/heads/main/debloat.ps1 | Invoke-Expression"
```
