param(
  [ValidateSet('NewFile', 'ReadFile', 'ReplaceFile')]
  [string]$Mode
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AbsoluteWindowsPath([string]$Path, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains([char]0) -or
    $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.IndexOf(':', 2) -ge 0) {
    throw "$Label must be an absolute path on a local fixed drive."
  }
  $driveName = $Path.Substring(0, 1)
  $drive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction Stop
  $driveInfo = New-Object IO.DriveInfo("${driveName}:\")
  if ($null -ne $drive.DisplayRoot -or $driveInfo.DriveType -ne [IO.DriveType]::Fixed) {
    throw "$Label must not use a mapped drive, UNC path, or removable media."
  }
}

function Assert-NoReparsePointInPath([string]$Path, [string]$Label) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetPathRoot($fullPath)
  $current = $root
  $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
  if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label must not traverse a reparse point."
  }
  foreach ($segment in $fullPath.Substring($root.Length).Split(
      [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
      [StringSplitOptions]::RemoveEmptyEntries)) {
    $current = Join-Path $current $segment
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Label must not traverse a reparse point."
    }
  }
}

function Resolve-ExistingFile([string]$Path, [string]$Label) {
  Assert-AbsoluteWindowsPath $Path $Label
  $fullPath = [IO.Path]::GetFullPath($Path)
  Assert-NoReparsePointInPath $fullPath $Label
  $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
  if ($item.PSProvider.Name -ne 'FileSystem' -or $item.PSIsContainer -or
    (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "$Label must be a regular file."
  }
  return $fullPath
}

function Resolve-ExistingDirectory([string]$Path, [string]$Label) {
  Assert-AbsoluteWindowsPath $Path $Label
  $fullPath = [IO.Path]::GetFullPath($Path)
  Assert-NoReparsePointInPath $fullPath $Label
  $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
  if ($item.PSProvider.Name -ne 'FileSystem' -or -not $item.PSIsContainer -or
    (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "$Label must be a regular directory."
  }
  $trimmed = $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $root = [IO.Path]::GetPathRoot($fullPath).TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if ($trimmed.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label must not be a volume root."
  }
  return $trimmed
}

function Get-Sid([object]$Identity) {
  try {
    if ($Identity -is [Security.Principal.SecurityIdentifier]) { return $Identity.Value }
    $reference = if ($Identity -is [Security.Principal.IdentityReference]) {
      $Identity
    } else {
      New-Object Security.Principal.NTAccount([string]$Identity)
    }
    return $reference.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    throw 'An ACL identity could not be verified.'
  }
}

function Assert-PrivateAcl(
  [string]$Path,
  [string]$Label,
  [bool]$RequireProtectedInheritance,
  [bool]$RequireCurrentModify = $false
) {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $allowedSids = @(
    $currentSid,
    'S-1-5-18',       # LocalSystem
    'S-1-5-32-544'    # BUILTIN\Administrators, optional recovery identity
  )
  $acl = Get-Acl -LiteralPath $Path
  if ($RequireProtectedInheritance -and -not $acl.AreAccessRulesProtected) {
    throw "$Label must have protected ACL inheritance."
  }
  $ownerSid = Get-Sid $acl.Owner
  if ($allowedSids -notcontains $ownerSid) {
    throw "$Label owner is not allowed."
  }
  $currentUserCanRead = $false
  $currentUserCanModify = $false
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
      throw "$Label must not contain Deny ACEs."
    }
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = Get-Sid $rule.IdentityReference
    if ($allowedSids -notcontains $sid) {
      throw "$Label has an Allow ACE for an unauthorized identity."
    }
    if ($sid -eq $currentSid) {
      if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -ne 0) {
        $currentUserCanRead = $true
      }
      if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq
        [Security.AccessControl.FileSystemRights]::Modify) {
        $currentUserCanModify = $true
      }
    }
  }
  if (-not $currentUserCanRead) { throw "$Label does not allow the current account to read." }
  if ($RequireCurrentModify -and -not $currentUserCanModify) {
    throw "$Label does not allow the current account to modify."
  }
}

function Assert-NoUnauthorizedWriteAcl(
  [string]$Path,
  [string]$Label,
  [bool]$RequireProtectedInheritance
) {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $allowedSids = @(
    $currentSid,
    'S-1-5-18',       # LocalSystem
    'S-1-5-32-544',   # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
  )
  $writeMask = [Security.AccessControl.FileSystemRights]::WriteData `
    -bor [Security.AccessControl.FileSystemRights]::AppendData `
    -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
    -bor [Security.AccessControl.FileSystemRights]::WriteAttributes `
    -bor [Security.AccessControl.FileSystemRights]::Delete `
    -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
    -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
    -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $acl = Get-Acl -LiteralPath $Path
  if ($RequireProtectedInheritance -and -not $acl.AreAccessRulesProtected) {
    throw "$Label must have protected ACL inheritance."
  }
  $ownerSid = Get-Sid $acl.Owner
  if ($allowedSids -notcontains $ownerSid) {
    throw "$Label owner is not trusted."
  }
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($rule.FileSystemRights -band $writeMask) -eq 0) { continue }
    $sid = Get-Sid $rule.IdentityReference
    if ($allowedSids -notcontains $sid) {
      throw "$Label lets an unauthorized identity modify executable content."
    }
  }
}

function Assert-NoUntrustedNamespaceReplacement([string]$Directory, [string]$Label) {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $trustedSids = @(
    $currentSid,
    'S-1-5-18',       # LocalSystem
    'S-1-5-32-544',   # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
  )
  $namespaceMutationMask = [Security.AccessControl.FileSystemRights]::Delete `
    -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
    -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
    -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $current = [IO.Path]::GetFullPath($Directory)
  while ($true) {
    $acl = Get-Acl -LiteralPath $current
    $ownerSid = Get-Sid $acl.Owner
    if ($trustedSids -notcontains $ownerSid) {
      throw "$Label namespace has an untrusted owner."
    }
    foreach ($rule in $acl.Access) {
      if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
      if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
        continue
      }
      if (($rule.FileSystemRights -band $namespaceMutationMask) -eq 0) { continue }
      $sid = Get-Sid $rule.IdentityReference
      if ($trustedSids -notcontains $sid) {
        throw "$Label namespace can be replaced by an unauthorized identity."
      }
    }
    $root = [IO.Path]::GetPathRoot($current).TrimEnd(
      [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $trimmed = $current.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ($trimmed.Equals($root, [StringComparison]::OrdinalIgnoreCase)) { break }
    $current = [IO.Path]::GetDirectoryName($trimmed)
  }
}

function Assert-PrivateSecretPath([string]$Path, [string]$SelectedMode) {
  Assert-AbsoluteWindowsPath $Path 'Secret path'
  $fullPath = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetPathRoot($fullPath)
  $trimmedRoot = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $trimmedPath = $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if ($trimmedPath.Equals($trimmedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The secret path must not be a volume root.'
  }
  $parent = [IO.Path]::GetDirectoryName($trimmedPath)
  if ([string]::IsNullOrWhiteSpace($parent) -or
    $parent.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Equals(
      $trimmedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The secret parent must not be a volume root.'
  }
  $privateParent = Resolve-ExistingDirectory $parent 'Secret parent'
  Assert-NoUntrustedNamespaceReplacement $privateParent 'Secret parent'
  Assert-PrivateAcl $privateParent 'Secret parent' $true $true
  if ($SelectedMode -eq 'NewFile') {
    if (Test-Path -LiteralPath $fullPath) { throw 'The secret file already exists.' }
    return
  }
  $privateFile = Resolve-ExistingFile $fullPath 'Secret file'
  Assert-PrivateAcl $privateFile 'Secret file' $false ($SelectedMode -eq 'ReplaceFile')
}

if ($MyInvocation.InvocationName -ne '.') {
  try {
    if ($env:OS -ne 'Windows_NT' -or [string]::IsNullOrWhiteSpace($Mode)) {
      throw 'Invalid Windows private-path gate invocation.'
    }
    [Console]::InputEncoding = New-Object Text.UTF8Encoding($false, $true)
    $selectedPath = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($selectedPath) -or $selectedPath.Length -gt 32768) {
      throw 'Invalid Windows private-path gate invocation.'
    }
    Assert-PrivateSecretPath $selectedPath $Mode
  } catch {
    [Console]::Error.WriteLine('windows-private-path-gate: path or ACL is not private.')
    exit 1
  }
}
