<#
.SYNOPSIS
  Seletor de capability preset do firmware AegisKey (build + checagem de orcamento).
.DESCRIPTION
  Menu interativo ou args (--cap/--board) sobre scripts/capability-catalog.json
  (fonte unica da verdade). Monta o `cargo +esp build` correto por preset+placa,
  converte ELF->.bin via esptool, compara com a factory do layout de particoes
  e RECUSA continuar em overflow (exit 1). Nunca grava hardware: flash continua
  manual via scripts/build-*.ps1 -Flash (exige placa + aprovacao).
  Portavel: so caminhos relativos ao repo; TargetDir via --target-dir, env ou
  .cargo/config.toml; sem machine paths novos (o fallback v5.3.1 segue a
  convenção shell-local ja registrada no .cargo/config.toml).
.EXAMPLE
  .\scripts\select-capability.ps1 --list-caps
  .\scripts\select-capability.ps1 --cap fido-only --board devkitc --release
  .\scripts\select-capability.ps1   # menu interativo
#>
param([string[]]$Args)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$CatalogPath = Join-Path $RepoRoot 'scripts\capability-catalog.json'
$TargetDirOverride = $null
$Profile = 'release'
$ListCaps = $false
$ListPools = $false
$WantHelp = $false
$CapArg = $null
$BoardArg = $null

function Show-Usage {
  Write-Host 'Uso:' -ForegroundColor Cyan
  Write-Host '  select-capability.ps1 [--cap fido-only|fido-totp|full] [--board devkitc|tdisplay|ttgo-classic] [--release|--debug]'
  Write-Host '                          [--list-caps] [--list-pools] [--catalog PATH] [--target-dir DIR] [--help]'
  Write-Host ''
  Write-Host '  Sem --cap/--board abre o menu interativo. --list-caps/--list-pools imprimem'
  Write-Host '  o catalogo (scripts/capability-catalog.json) e saem. O script compila, mede'
  Write-Host '  o .bin e compara com a factory do layout: PASS continua, FAIL (overflow)'
  Write-Host '  sai com codigo 1 e recusa continuar. Flash e sempre manual.'
}

# --- parse manual (aceita -x e --xxx, igual ao .sh) ---
$idx = 0
while ($idx -lt $Args.Count) {
  $a = $Args[$idx]
  switch -Regex ($a) {
    '^(-{1,2}help|-[?h])$'   { $WantHelp = $true }
    '^(-{1,2}list-caps)$'    { $ListCaps = $true }
    '^(-{1,2}list-pools)$'   { $ListPools = $true }
    '^(-{1,2}release)$'      { $Profile = 'release' }
    '^(-{1,2}debug)$'        { $Profile = 'debug' }
    '^(-{1,2}cap)$'          { $idx++; $CapArg = $Args[$idx] }
    '^(-{1,2}board)$'        { $idx++; $BoardArg = $Args[$idx] }
    '^(-{1,2}catalog)$'      { $idx++; $CatalogPath = $Args[$idx] }
    '^(-{1,2}target-dir)$'   { $idx++; $TargetDirOverride = $Args[$idx] }
    default { Write-Host ("[ERRO] arg desconhecido: {0}" -f $a) -ForegroundColor Red; Show-Usage; exit 1 }
  }
  $idx++
}
if ($WantHelp) { Show-Usage; exit 0 }
if (-not (Test-Path -LiteralPath $CatalogPath)) { Write-Host ("[ERRO] catalogo nao encontrado: {0}" -f $CatalogPath) -ForegroundColor Red; exit 1 }
$cat = Get-Content -Raw -LiteralPath $CatalogPath | ConvertFrom-Json

function Format-Bytes([int64]$b) {
  if ($b -ge 1048576) { return ('{0:N2} MiB' -f ($b / 1048576)) }
  if ($b -ge 1024) { return ('{0:N1} KiB' -f ($b / 1024)) }
  return ("$b B")
}

function Show-Caps {
  Write-Host '== CAPABILITIES (fonte: scripts/capability-catalog.json) ==' -ForegroundColor Cyan
  Write-Host 'Custos flash sao ESTIMATIVAS (modulo-fonte proporcional, calibrado no build full medido);' -ForegroundColor DarkGray
  Write-Host 'modulos compartilhados aparecem em cada capability (nao somar). Totais de preset sao MEDIDOS.' -ForegroundColor DarkGray
  foreach ($c in $cat.capabilities) {
    $presets = ($c.presets -join ',')
    $cost = if ($c.flash_cost_est_bytes -eq 0) { '(compartilhado, ver notas)' } else { ('~' + (Format-Bytes $c.flash_cost_est_bytes) + ' est.') }
    Write-Host ("  {0,-24} presets=[{1,-22}] feature: {2,-46} {3}" -f $c.id, $presets, $c.feature, $cost)
  }
}

function Show-Pools {
  Write-Host '== STORAGE POOLS (fonte: scripts/capability-catalog.json) ==' -ForegroundColor Cyan
  foreach ($p in $cat.pools) {
    if ($p.kind -eq 'budget') { Write-Host ("  [budget] {0}: {1}" -f $p.id, (Format-Bytes $p.est_total_bytes)) -ForegroundColor Yellow }
    else {
      $cons = if ($p.consumed_by.Count -eq 0) { '(sempre residente/transiente)' } else { ($p.consumed_by -join ',') }
      Write-Host ("  [{0}] {1,-18} {2,-34} ~{3,-12} consome: {4}" -f $p.kind, $p.id, $p.slot_limit, (Format-Bytes $p.est_total_bytes), $cons)
    }
  }
}

if ($ListCaps) { Show-Caps; exit 0 }
if ($ListPools) { Show-Pools; exit 0 }

function Get-Preset([string]$id) { return $cat.presets.$id }
function Get-Board([string]$id) { return $cat.boards.$id }

# --- menu interativo ---
function Ask-Choice([string]$title, [array]$options) {
  Write-Host ("`n{0}" -f $title) -ForegroundColor Yellow
  for ($i = 0; $i -lt $options.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $options[$i]) }
  while ($true) {
    $r = Read-Host ("Escolha [1-{0}]" -f $options.Count)
    if ($r -match '^\d+$' -and [int]$r -ge 1 -and [int]$r -le $options.Count) { return ($r - 1) }
  }
}

$capId = $CapArg
if (-not $capId) {
  $names = @('full', 'fido-only', 'fido-totp') | ForEach-Object { "$_ — " + (Get-Preset $_).blurb }
  $capId = @('full', 'fido-only', 'fido-totp')[(Ask-Choice 'PRESET DE CAPABILITY:' $names)]
}
if (-not (Get-Preset $capId)) { Write-Host ("[ERRO] preset invalido: {0} (use full|fido-only|fido-totp)" -f $capId) -ForegroundColor Red; exit 1 }
$preset = Get-Preset $capId

$boardId = $BoardArg
if (-not $boardId) {
  $names = @('devkitc', 'tdisplay', 'ttgo-classic') | ForEach-Object { "$_ — " + (Get-Board $_).name }
  $boardId = @('devkitc', 'tdisplay', 'ttgo-classic')[(Ask-Choice 'PLACA:' $names)]
}
if (-not (Get-Board $boardId)) { Write-Host ("[ERRO] placa invalida: {0}" -f $boardId) -ForegroundColor Red; exit 1 }
$board = Get-Board $boardId

if ($preset.boards -notcontains $boardId) {
  Write-Host ("[ERRO] preset '{0}' so serve a placa: {1} (diet = devkitc/2MB; display exige full)." -f $capId, ($preset.boards -join ',')) -ForegroundColor Red
  exit 1
}

# --- detalhe includes/excludes + pools ---
Write-Host ("`nPreset: {0}  |  Placa: {1}  |  Profile: {2}" -f $preset.name, $board.name, $Profile) -ForegroundColor Cyan
Write-Host 'Inclui:' -ForegroundColor Green
foreach ($id in $preset.includes) {
  $c = ($cat.capabilities | Where-Object { $_.id -eq $id })[0]
  $cost = if ($c.flash_cost_est_bytes -eq 0) { '(custo contado no grupo)' } else { ('~' + (Format-Bytes $c.flash_cost_est_bytes) + ' est.') }
  Write-Host ("  + {0,-24} [{1}] {2}" -f $id, $c.feature, $cost)
}
if ($preset.excludes.Count -gt 0) {
  Write-Host 'Exclui (0x06 UNSUPPORTED_FEATURE fail-closed onde for comando):' -ForegroundColor Yellow
  foreach ($id in $preset.excludes) { Write-Host ("  - {0}" -f $id) }
}
$storageBudget = [int64]$board.storage_bytes
$resident = @($cat.pools | Where-Object {
  $_.kind -eq 'resident' -and ($_.always -or (($_.consumed_by | Where-Object { $preset.includes -contains $_ }).Count -gt 0))
})
$resTotal = [int64]($resident | Measure-Object -Property est_total_bytes -Sum).Sum
Write-Host 'Pools NVS residentes do preset:' -ForegroundColor Cyan
foreach ($p in $resident) { Write-Host ("  {0,-16} {1,-30} ~{2}" -f $p.id, $p.slot_limit, (Format-Bytes $p.est_total_bytes)) }
$pct = [math]::Round(100.0 * $resTotal / $storageBudget, 1)
if ($resTotal -le $storageBudget) { Write-Host ("  NVS residente: ~{0} / {1} ({2}%) PASS" -f (Format-Bytes $resTotal), (Format-Bytes $storageBudget), $pct) -ForegroundColor Green }
else { Write-Host ("  NVS residente: ~{0} / {1} ({2}%) WARN: excede o storage do layout!" -f (Format-Bytes $resTotal), (Format-Bytes $storageBudget), $pct) -ForegroundColor Red }
$staging = ($cat.pools | Where-Object { $_.id -eq 'ota-staging' })[0]
if ([int64]$staging.est_total_bytes -le $storageBudget) { Write-Host ("  OTA staging (transiente): ~{0} cabe no storage PASS" -f (Format-Bytes $staging.est_total_bytes)) -ForegroundColor Green }
else { Write-Host ("  OTA staging (transiente): ~{0} NAO cabe no storage ({1}) WARN: no layout 2MB o fluxo precisa transmitir por streaming, sem estagiar a imagem cheia." -f (Format-Bytes $staging.est_total_bytes), (Format-Bytes $storageBudget)) -ForegroundColor Yellow }
Write-Host ("  Layout: {0} | factory 0x{1:X} ({2})" -f $board.partition_file, [int64]$board.factory_bytes, (Format-Bytes $board.factory_bytes)) -ForegroundColor DarkGray
if ($preset.goal_bytes) { Write-Host ("  Meta do preset: <={0} (info; o gate e a factory)" -f (Format-Bytes ([int64]$preset.goal_bytes))) -ForegroundColor DarkGray }

if (-not $CapArg -or -not $BoardArg) {
  $ok = Read-Host 'Confirmar build com este orcamento? [S/n]'
  if ($ok -ne '' -and $ok.ToLowerInvariant() -ne 's' -and $ok.ToLowerInvariant() -ne 'y') { Write-Host 'Cancelado.'; exit 1 }
}

# --- ambiente ESP (shell-local v5.3.1 quando presente; senao usa o env atual) ---
function Initialize-PickerEsp {
  $preferredIdf = 'C:\.embuild\espressif\esp-idf\v5.3.1'
  if (Test-Path -LiteralPath $preferredIdf) {
    $env:IDF_PATH = $preferredIdf
    $env:ESP_IDF_VERSION = 'v5.3.1'
    $env:IDF_TOOLS_PATH = 'C:\.embuild\espressif'
  } elseif (-not $env:IDF_PATH) {
    Write-Host '[ERRO] EXTERNAL_BLOCKED: IDF_PATH ausente e v5.3.1 shell-local nao encontrado. Rode export-esp/espup ou defina IDF_PATH.' -ForegroundColor Red
    exit 2
  } else {
    Write-Host ("[WARN] usando IDF_PATH existente: {0}" -f $env:IDF_PATH) -ForegroundColor Yellow
  }
  $env:ESP_IDF_SDKCONFIG_DEFAULTS = Join-Path $RepoRoot 'sdkconfig.defaults.esp32s3'
  $env:CARGO_WORKSPACE_DIR = $RepoRoot
  $env:ESP_IDF_TOOLS_INSTALL_DIR = 'fromenv'
  $userCargo = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cargo\bin'
  if (Test-Path -LiteralPath $userCargo) { $env:PATH = "$userCargo;$env:PATH" }
  $py = 'C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts'
  if (Test-Path -LiteralPath $py) { $env:PATH = "$py;$env:PATH" }
  $cm = (Get-ChildItem 'C:\.embuild\espressif\tools\cmake\*\bin' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
  if ($cm) { $env:PATH = "$cm;$env:PATH" }
  $nj = (Get-ChildItem 'C:\.embuild\espressif\tools\ninja\*' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
  if ($nj) { $env:PATH = "$nj;$env:PATH" }
  $gcc = (Get-ChildItem 'C:\.embuild\espressif\tools\xtensa-esp-elf\*\xtensa-esp-elf\bin' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
  if ($gcc) { $env:PATH = "$gcc;$env:PATH" }
  $toolsDir = Join-Path $env:IDF_PATH 'tools'
  if (Test-Path -LiteralPath $toolsDir) { $env:PATH = "$toolsDir;$env:PATH" }
  try { & cargo +esp --version | Out-Null } catch {
    Write-Host '[ERRO] EXTERNAL_BLOCKED: toolchain `esp` ausente (`cargo +esp --version` falhou). Instale via espup.' -ForegroundColor Red
    exit 2
  }
}

function Resolve-TargetDir {
  if ($TargetDirOverride) { return $TargetDirOverride }
  $cfg = Join-Path $RepoRoot '.cargo\config.toml'
  if (Test-Path -LiteralPath $cfg) {
    $m = Select-String -LiteralPath $cfg -Pattern '^\s*target-dir\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($m -and (Test-Path -LiteralPath $m.Matches[0].Groups[1].Value)) { return $m.Matches[0].Groups[1].Value }
  }
  $repoTarget = Join-Path $RepoRoot 'target'
  if (Test-Path -LiteralPath $repoTarget) { return $repoTarget }
  return $repoTarget
}

Initialize-PickerEsp
$targetDir = Resolve-TargetDir
Write-Host ("TargetDir: {0}" -f $targetDir) -ForegroundColor DarkGray

$features = $board.board_feature
if ($preset.extra_features.Count -gt 0) { $features += ',' + ($preset.extra_features -join ',') }
$target = $board.target
$chip = $board.chip
$binName = $board.bin_prefix + $(if ($preset.diet) { '-' + $capId } else { '' }) + '.bin'

$buildArgs = @('+esp', 'build', '-p', 'aegis-fido-firmware', '--target', $target, "--$Profile",
  '--no-default-features', '--features', $features, '-Zbuild-std=std,panic_abort')
Write-Host ("`nBuild: cargo {0}" -f ($buildArgs -join ' ')) -ForegroundColor Cyan
if ($boardId -eq 'ttgo-classic') { $env:CARGO_PROFILE_RELEASE_OPT_LEVEL = 'z' }
if ($TargetDirOverride) { $env:CARGO_TARGET_DIR = $TargetDirOverride }
Push-Location $RepoRoot
try { & cargo @buildArgs } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { Write-Host ("[ERRO] build falhou (exit {0})." -f $LASTEXITCODE) -ForegroundColor Red; exit 1 }
Write-Host '[OK] firmware ELF compilado.' -ForegroundColor Green

# --- elf2image ---
$elfPath = Join-Path $targetDir "$target\$Profile\aegis-fido-firmware"
$outBin = Join-Path $targetDir $binName
if (-not (Test-Path -LiteralPath $elfPath)) { Write-Host ("[ERRO] ELF nao encontrado: {0}" -f $elfPath) -ForegroundColor Red; exit 1 }
function Find-Esptool {
  $pyScripts = 'C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts'
  $hard = Join-Path $pyScripts 'esptool.exe'
  if (Test-Path -LiteralPath $hard) { return $hard }
  foreach ($cand in @('esptool.exe', 'esptool.py')) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) { return $cand }
  }
  return $null
}
$esptool = Find-Esptool
Write-Host ("Convertendo ELF->bin ({0})..." -f $chip) -ForegroundColor Cyan
if ($esptool -and $esptool -ne 'esptool.py') { & $esptool --chip $chip elf2image --flash_size 4MB -o $outBin $elfPath }
elseif ($esptool) { & python $esptool --chip $chip elf2image --flash_size 4MB -o $outBin $elfPath }
else {
  try { & python -m esptool --chip $chip elf2image --flash_size 4MB -o $outBin $elfPath }
  catch { Write-Host '[ERRO] EXTERNAL_BLOCKED: esptool ausente (PATH, IDF Scripts ou `python -m esptool`).' -ForegroundColor Red; exit 2 }
}
if ($LASTEXITCODE -ne 0) { Write-Host '[ERRO] elf2image falhou.' -ForegroundColor Red; exit 1 }

$sha = (Get-FileHash -LiteralPath $outBin -Algorithm SHA256).Hash
"$sha  $(Split-Path $outBin -Leaf)" | Set-Content -LiteralPath ($outBin + '.sha256') -Encoding ASCII
$size = (Get-Item -LiteralPath $outBin).Length
$factory = [int64]$board.factory_bytes
Write-Host ("`nSHA256: {0}" -f $sha) -ForegroundColor DarkGray
Write-Host ("SIZE:   {0} bytes ({1})" -f $size, (Format-Bytes $size)) -ForegroundColor DarkGray
Write-Host ("BUDGET: {0} bytes ({1}) [factory {2}]" -f $factory, (Format-Bytes $factory), $board.partition_file) -ForegroundColor DarkGray
if ($preset.goal_bytes -and $size -gt [int64]$preset.goal_bytes) {
  Write-Host ("WARN: acima da meta do preset ({0})." -f (Format-Bytes ([int64]$preset.goal_bytes))) -ForegroundColor Yellow
}
if ($size -gt $factory) {
  Write-Host ("FAIL: imagem ({0} B) nao cabe na factory ({1} B). Recusando continuar." -f $size, $factory) -ForegroundColor Red
  exit 1
}
Write-Host ("PASS: {0} cabe na factory ({1} de {2})." -f (Split-Path $outBin -Leaf), (Format-Bytes $size), (Format-Bytes $factory)) -ForegroundColor Green
Write-Host "`nFlash continua manual (exige placa + aprovacao):" -ForegroundColor Yellow
Write-Host ("  Layout: {0} (factory offset 0x10000)" -f $board.partition_file)
Write-Host ("  .\scripts\build-esp32s3-devkitc.ps1 -Flash   # exemplo (placa devkitc)")
exit 0