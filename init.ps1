# init.ps1
param(
    [string]$ProjectName = "zap-kb",
    # Use "github.com/yourusername/zap-kb" if you plan to publish; otherwise local name is fine
    [string]$GoModulePath = "zap-kb"
)

# Paths
$CurrentPath = Get-Location
$ProjectPath = Join-Path $CurrentPath $ProjectName

Write-Host "Creating Go project at: $ProjectPath" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $ProjectPath -Force | Out-Null

# Directories
$dirs = @(
    "cmd\$ProjectName",
    "internal",
    "pkg",
    "docs",
    "scripts",
    "test",
    "bin"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Path (Join-Path $ProjectPath $dir) -Force | Out-Null
}

# README.md
@"
# $ProjectName

Go-based project for integrating ZAP scan results into a Knowledge Base.

## Getting Started
- WSL (Ubuntu) recommended for `make`
- Run:
    make run
"@ | Out-File -FilePath (Join-Path $ProjectPath "README.md") -Encoding UTF8 -Force

# .gitignore
@"
# Binaries
bin/
*.exe
*.dll
*.so
*.dylib

# Build
*.test
*.out

# Dependency directories
vendor/

# IDE/editor settings
.vscode/
.idea/
"@ | Out-File -FilePath (Join-Path $ProjectPath ".gitignore") -Encoding UTF8 -Force

# main.go (hello world)
@"
package main

import "fmt"

func main() {
    fmt.Println("Starting $ProjectName...")
}
"@ | Out-File -FilePath (Join-Path $ProjectPath "cmd\$ProjectName\main.go") -Encoding UTF8 -Force

# Makefile (use literal tabs + literal $(APP_NAME))
$makefile = @"
APP_NAME := $ProjectName

.PHONY: build run test clean

build:
`tgo build -o bin/`$(APP_NAME) ./cmd/`$(APP_NAME)

run:
`tgo run ./cmd/`$(APP_NAME)

test:
`tgo test ./...

clean:
`trm -rf bin
"@

# IMPORTANT: Write ASCII so tabs are preserved; the backticks above produce real TABs and literal $.
Set-Content -Path (Join-Path $ProjectPath "Makefile") -Value $makefile -Encoding ascii

# Go mod init via WSL (so modules are Linux-native)
Write-Host "Initializing Go module in WSL..." -ForegroundColor Yellow
wsl bash -lc "cd '$(wslpath -a $ProjectPath)' && go mod init $GoModulePath && go mod tidy"

Write-Host "`nGo project initialized successfully!" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1) wsl"
Write-Host "  2) cd $(wslpath -a $ProjectPath)"
Write-Host "  3) sudo apt update && sudo apt install -y make   # if 'make' not found"
Write-Host "  4) make run   # or: go run ./cmd/$ProjectName"
