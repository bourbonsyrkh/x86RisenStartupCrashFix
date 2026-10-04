param(
    [Parameter(Mandatory = $true)]
    [string]$Source,
    [string]$Output
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $PSScriptRoot 'dist\SHW32.DLL'
}

# This patch is intentionally tied to the exact SmartHeap build in the crash dump.
$expectedHash = 'C59315DC66BC0A21988C4AF419C213F793D3B04B4511BE136556034EFD25CC38'
$actualHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw "Unexpected SHW32.DLL SHA-256: $actualHash"
}

$file = [IO.File]::ReadAllBytes($Source)
$pe = [BitConverter]::ToInt32($file, 0x3c)
if ([BitConverter]::ToUInt16($file, $pe + 4) -ne 0x14c) {
    throw 'Expected a 32-bit x86 DLL.'
}

$imageBase = [BitConverter]::ToUInt32($file, $pe + 24 + 28)
if ($imageBase -ne 0x0a930000) {
    throw 'Unexpected preferred image base.'
}

# All RVAs below were matched against the crash dump and this exact file.
$entryRva = 0x0f260                 # shi_free
$resumeRva = $entryRva + 5
$caveRva = 0x23600                  # unused INT3 padding in executable .text
$virtualQueryIatRva = 0x353e8     # KERNEL32!VirtualQuery import slot
$textRaw = 0x400
$textRva = 0x1000
function TextOffset([int]$rva) { return $textRaw + $rva - $textRva }

$entryOffset = TextOffset $entryRva
$caveOffset = TextOffset $caveRva
$originalPrologue = [byte[]](0x56, 0x8b, 0x74, 0x24, 0x08)
for ($i = 0; $i -lt $originalPrologue.Length; $i++) {
    if ($file[$entryOffset + $i] -ne $originalPrologue[$i]) {
        throw 'shi_free prologue differs from the analyzed build.'
    }
}

$script:code = [Collections.Generic.List[byte]]::new()
$script:labels = @{}
$script:fixups = [Collections.Generic.List[object]]::new()
function Emit([byte[]]$bytes) { $script:code.AddRange($bytes) }
function Label([string]$name) { $script:labels[$name] = $script:code.Count }
function Rel32([byte[]]$opcode, [string]$target) {
    Emit $opcode
    $at = $script:code.Count
    Emit ([byte[]](0, 0, 0, 0))
    $script:fixups.Add([pscustomobject]@{ At = $at; Target = $target })
}

# Keep the original calling convention: shi_free is cdecl and returns void.
# VirtualQuery checks the 64 KiB arena header that MemFreePtr would read.
Emit ([byte[]](0x53, 0x8b, 0x5c, 0x24, 0x08, 0x85, 0xdb)) # push ebx; mov ebx,[esp+8]; test ebx,ebx
Rel32 ([byte[]](0x0f, 0x84)) 'resume'               # null is already accepted by original code
Emit ([byte[]](0x81, 0xe3, 0x00, 0x00, 0xff, 0xff)) # and ebx,0xffff0000
Emit ([byte[]](0x83, 0xc3, 0x1c))                   # add ebx,0x1c
Emit ([byte[]](0x83, 0xec, 0x20, 0x8d, 0x04, 0x24)) # sub esp,32; lea eax,[esp]
Emit ([byte[]](0x6a, 0x1c, 0x50, 0x53))             # VirtualQuery(ebx,buffer,28)
Emit ([byte[]](0xe8, 0, 0, 0, 0))                   # call next; pop gets current module address
Label 'popAddress'
Emit ([byte[]](0x58, 0x2d))                         # pop eax; sub eax,popAddressRva
$popRvaOperand = $script:code.Count
Emit ([byte[]](0, 0, 0, 0))
Emit ([byte[]](0x05))                               # add eax,VirtualQueryIatRva
Emit ([BitConverter]::GetBytes([int]$virtualQueryIatRva))
Emit ([byte[]](0xff, 0x10, 0x85, 0xc0))             # call dword ptr [eax]; test eax,eax
Rel32 ([byte[]](0x0f, 0x84)) 'invalid'
Emit ([byte[]](0x81, 0x7c, 0x24, 0x10, 0x00, 0x10, 0x00, 0x00)) # State == MEM_COMMIT
Rel32 ([byte[]](0x0f, 0x85)) 'invalid'
Emit ([byte[]](0x8b, 0x44, 0x24, 0x14, 0xa9, 0x01, 0x01, 0x00, 0x00)) # Protect & (NOACCESS|GUARD)
Rel32 ([byte[]](0x0f, 0x85)) 'invalid'
Emit ([byte[]](0x83, 0xc4, 0x20))                   # release VirtualQuery buffer
Label 'resume'
Emit ([byte[]](0x5b))                               # restore ebx
Emit $originalPrologue                             # original shi_free instructions
Rel32 ([byte[]](0xe9)) 'originalResume'
Label 'invalid'
Emit ([byte[]](0x83, 0xc4, 0x20, 0x5b, 0xc3))       # discard invalid free, return

$script:labels['originalResume'] = $resumeRva - $caveRva
$popRva = $caveRva + $script:labels['popAddress']
$popBytes = [BitConverter]::GetBytes([int]$popRva)
for ($i = 0; $i -lt 4; $i++) { $script:code[$popRvaOperand + $i] = $popBytes[$i] }
foreach ($fixup in $script:fixups) {
    $targetRva = $caveRva + $script:labels[$fixup.Target]
    $nextRva = $caveRva + $fixup.At + 4
    $rel = [int]($targetRva - $nextRva)
    $bytes = [BitConverter]::GetBytes($rel)
    for ($i = 0; $i -lt 4; $i++) { $script:code[$fixup.At + $i] = $bytes[$i] }
}

if ($script:code.Count -gt 0x100) {
    throw 'Patch exceeds the verified code cave.'
}
for ($i = 0; $i -lt $script:code.Count; $i++) {
    if ($file[$caveOffset + $i] -ne 0xcc) {
        throw ('Code cave is occupied at RVA 0x{0:X}.' -f ($caveRva + $i))
    }
    $file[$caveOffset + $i] = $script:code[$i]
}

$detour = [byte[]](0xe9, 0, 0, 0, 0)
$jump = [BitConverter]::GetBytes([int]($caveRva - $resumeRva))
for ($i = 0; $i -lt 4; $i++) { $detour[$i + 1] = $jump[$i] }
for ($i = 0; $i -lt 5; $i++) { $file[$entryOffset + $i] = $detour[$i] }

$directory = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory | Out-Null
}
[IO.File]::WriteAllBytes($Output, $file)
Write-Output ('Built {0}; patch size {1} bytes; SHA-256 {2}' -f $Output, $script:code.Count, (Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash)
