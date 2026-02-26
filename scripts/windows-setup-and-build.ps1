param(
  [switch]$SkipTests,
  [switch]$Release,
  [switch]$Installer
)

$ErrorActionPreference = "Stop"

function Require-Command($name, $help) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "$name is required. $help"
  }
}

Write-Host "[AI Armor] validating local build prerequisites..."
Require-Command "cargo" "Install Rust from https://rustup.rs/ and re-open PowerShell."

if ($Installer) {
  if (-not (Get-Command "cargo-tauri" -ErrorAction SilentlyContinue)) {
    Write-Host "[AI Armor] installing cargo-tauri CLI..."
    cargo install tauri-cli --locked
  }
}

Write-Host "[AI Armor] fetching dependencies..."
cargo fetch

if (-not $SkipTests) {
  Write-Host "[AI Armor] running core tests..."
  cargo test -p core-detect -p core-tokenize -p core-vault
}

Push-Location apps/desktop-tauri/src-tauri
try {
  if ($Installer) {
    Write-Host "[AI Armor] building installer bundle (tauri)..."
    cargo tauri build
    Write-Host "[AI Armor] installer artifacts at apps/desktop-tauri/src-tauri/target/release/bundle"
  }
  elseif ($Release) {
    Write-Host "[AI Armor] building release binary..."
    cargo build --release
    Write-Host "[AI Armor] binary at apps/desktop-tauri/src-tauri/target/release/desktop-tauri.exe"
  }
  else {
    Write-Host "[AI Armor] starting desktop app in dev mode..."
    cargo run
  }
}
finally {
  Pop-Location
}
