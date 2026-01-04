function nightly_version($quiet = $false) {
    if (!$quiet) {
        warn "This is a nightly version. Downloaded files won't be verified."
    }
    return "nightly-$(Get-Date -Format 'yyyyMMdd')"
}

function install_app($app, $architecture, $global, $suggested, $use_cache = $true, $check_hash = $true) {
    $app, $manifest, $bucket, $url = Get-Manifest $app

    if (!$manifest) {
        abort "Couldn't find manifest for '$app'$(if ($bucket) { " from '$bucket' bucket" } elseif ($url) { " at '$url'" })."
    }

    $version = $manifest.version
    if (!$version) { abort "Manifest doesn't specify a version." }
    if ($version -match '[^\w\.\-\+_]') {
        abort "Manifest version has unsupported character '$($matches[0])'."
    }

    $is_nightly = $version -eq 'nightly'
    if ($is_nightly) {
        $version = nightly_version
        $check_hash = $false
    }

    $architecture = Get-SupportedArchitecture $manifest $architecture
    if ($null -eq $architecture) {
        error "'$app' doesn't support current architecture!"
        return
    }

    if ((get_config SHOW_MANIFEST $false) -and ($MyInvocation.ScriptName -notlike '*scoop-update*')) {
        Write-Host "Manifest: $app.json"
        $style = get_config CAT_STYLE
        if ($style) {
            $manifest | ConvertToPrettyJson | bat --no-paging --style $style --language json
        } else {
            $manifest | ConvertToPrettyJson
        }
        $answer = Read-Host -Prompt 'Continue installation? [Y/n]'
        if (($answer -eq 'n') -or ($answer -eq 'N')) {
            return
        }
    }
    Write-Output "Installing '$app' ($version) [$architecture]$(if ($bucket) { " from '$bucket' bucket" } else { " from '$url'" })"

    $dir = ensure (versiondir $app $version $global)
    $original_dir = $dir # keep reference to real (not linked) directory
    $persist_dir = persistdir $app $global

    $fname = Invoke-ScoopDownload $app $version $manifest $bucket $architecture $dir $use_cache $check_hash
    Invoke-Extraction -Path $dir -Name $fname -Manifest $manifest -ProcessorArchitecture $architecture
    Invoke-HookScript -HookType 'pre_install' -Manifest $manifest -ProcessorArchitecture $architecture

    Invoke-Installer -Path $dir -Name $fname -Manifest $manifest -ProcessorArchitecture $architecture -AppName $app -Global:$global
    ensure_install_dir_not_in_path $dir $global
    $dir = link_current $dir
    if ((get_config REVERSE_JUNCTION $false) -and !(get_config NO_JUNCTION)) {
        # In reverse_junction layout, 'current' is the real directory.
        $original_dir = $dir
    }
    create_shims $manifest $dir $global $architecture
    create_startmenu_shortcuts $manifest $dir $global $architecture
    install_psmodule $manifest $dir $global
    env_add_path $manifest $dir $global $architecture
    env_set $manifest $global $architecture

    # persist data
    persist_data $manifest $original_dir $persist_dir
    persist_permission $manifest $global

    Invoke-HookScript -HookType 'post_install' -Manifest $manifest -ProcessorArchitecture $architecture

    # save info for uninstall
    save_installed_manifest $app $bucket $dir $url
    save_install_info @{ 'architecture' = $architecture; 'url' = $url; 'bucket' = $bucket } $dir

    if ($manifest.suggest) {
        $suggested[$app] = $manifest.suggest
    }

    success "'$app' ($version) was installed successfully!"

    show_notes $manifest $dir $original_dir $persist_dir
}

function is_in_dir($dir, $check) {
    $check -match "^$([regex]::Escape("$dir"))([/\\]|$)"
}

function Invoke-Installer {
    [CmdletBinding()]
    param (
        [string]
        $Path,
        [string[]]
        $Name,
        [psobject]
        $Manifest,
        [Alias('Arch', 'Architecture')]
        [ValidateSet('32bit', '64bit', 'arm64')]
        [string]
        $ProcessorArchitecture,
        [string]
        $AppName,
        [switch]
        $Global,
        [switch]
        $Uninstall
    )
    $type = if ($Uninstall) { 'uninstaller' } else { 'installer' }
    $installer = arch_specific $type $Manifest $ProcessorArchitecture
    if ($installer.file -or $installer.args) {
        # Installer filename is either explicit defined ('installer.file') or file name in the first URL
        if (!$Name) {
            $Name = url_filename @(url $manifest $architecture)
        }
        $progName = "$Path\$(coalesce $installer.file $Name[0])"
        if (!(is_in_dir $Path $progName)) {
            abort "Error in manifest: $((Get-Culture).TextInfo.ToTitleCase($type)) $progName is outside the app directory."
        } elseif (!(Test-Path $progName)) {
            abort "$((Get-Culture).TextInfo.ToTitleCase($type)) $progName is missing."
        }
        $substitutions = @{
            '$dir'     = $Path
            '$global'  = $Global
            '$version' = $Manifest.version
        }
        $fnArgs = substitute $installer.args $substitutions
        if ($progName.EndsWith('.ps1')) {
            & $progName @fnArgs
        } else {
            $status = Invoke-ExternalCommand $progName -ArgumentList $fnArgs -Activity "Running $type ..."
            if (!$status) {
                if ($Uninstall) {
                    abort 'Uninstallation aborted.'
                } else {
                    abort "Installation aborted. You might need to run 'scoop uninstall $AppName' before trying again."
                }
            }
            # Don't remove installer if "keep" flag is set to true
            if (!$installer.keep) {
                Remove-Item $progName
            }
        }
    }
    Invoke-HookScript -HookType $type -Manifest $Manifest -ProcessorArchitecture $ProcessorArchitecture
}

function Invoke-HookScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('installer', 'pre_install', 'post_install', 'uninstaller', 'pre_uninstall', 'post_uninstall')]
        [String] $HookType,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $Manifest,
        [Parameter(Mandatory = $true)]
        [Alias('Arch', 'Architecture')]
        [ValidateSet('32bit', '64bit', 'arm64')]
        [string]
        $ProcessorArchitecture
    )

    $script = arch_specific $HookType $Manifest $ProcessorArchitecture
    if ($HookType -in @('installer', 'uninstaller')) {
        $script = $script.script
    }
    if ($script) {
        Write-Host "Running $HookType script..." -NoNewline
        Invoke-Command ([scriptblock]::Create($script -join "`r`n"))
        Write-Host 'done.' -ForegroundColor Green
    }
}

# get target, name, arguments for shim
function shim_def($item) {
    if ($item -is [array]) { return $item }
    return $item, (strip_ext (fname $item)), $null
}

function create_shims($manifest, $dir, $global, $arch) {
    $shims = @(arch_specific 'bin' $manifest $arch)
    $shims | Where-Object { $_ -ne $null } | ForEach-Object {
        $target, $name, $arg = shim_def $_
        Write-Output "Creating shim for '$name'."

        if (Test-Path "$dir\$target" -PathType leaf) {
            $bin = "$dir\$target"
        } elseif (Test-Path $target -PathType leaf) {
            $bin = $target
        } else {
            $bin = (Get-Command $target).Source
        }
        if (!$bin) { abort "Can't shim '$target': File doesn't exist." }

        shim $bin $global $name (substitute $arg @{ '$dir' = $dir; '$original_dir' = $original_dir; '$persist_dir' = $persist_dir })
    }
}

function rm_shim($name, $shimdir, $app) {
    '', '.shim', '.cmd', '.ps1' | ForEach-Object {
        $shimPath = "$shimdir\$name$_"
        $altShimPath = "$shimPath.$app"
        if ($app -and (Test-Path -Path $altShimPath -PathType Leaf)) {
            Write-Output "Removing shim '$name$_.$app'."
            Remove-Item $altShimPath
        } elseif (Test-Path -Path $shimPath -PathType Leaf) {
            Write-Output "Removing shim '$name$_'."
            Remove-Item $shimPath
            $oldShims = Get-Item -Path "$shimPath.*" -Exclude '*.shim', '*.cmd', '*.ps1'
            if ($null -eq $oldShims) {
                if ($_ -eq '.shim') {
                    Write-Output "Removing shim '$name.exe'."
                    Remove-Item -Path "$shimdir\$name.exe"
                }
            } else {
                (@($oldShims) | Sort-Object -Property LastWriteTimeUtc)[-1] | Rename-Item -NewName { $_.Name -replace '\.[^.]*$', '' }
            }
        }
    }
}

function rm_shims($app, $manifest, $global, $arch) {
    $shims = @(arch_specific 'bin' $manifest $arch)

    $shims | Where-Object { $_ -ne $null } | ForEach-Object {
        $target, $name, $null = shim_def $_
        $shimdir = shimdir $global

        rm_shim $name $shimdir $app
    }
}

# --- junction helpers ---
function Get-DirectoryLinkType([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item -isnot [System.IO.DirectoryInfo]) {
        return $null
    }
    return $item.LinkType
}
function Get-DirectoryLinkTarget([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item -isnot [System.IO.DirectoryInfo] -or [String]::IsNullOrEmpty($item.LinkType)) {
        return $null
    }
    $target = $item.Target
    if ($target -is [array]) {
        $target = $target[0]
    }
    return $target
}
function Remove-DirectoryLink([string] $Path) {
    $linkType = Get-DirectoryLinkType $Path
    if ([String]::IsNullOrEmpty($linkType)) {
        return $false
    }

    # remove read-only attribute on link
    attrib $Path -R /L | Out-Null

    # remove the junction
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    return $true
}
function Get-UniqueDirectoryPath([string] $Path) {
    if (!(Test-Path $Path)) {
        return $Path
    }
    $i = 1
    while (Test-Path "$Path($i)") {
        $i++
    }
    return "$Path($i)"
}
function Find-ActiveVersionFromReverseLayout([string] $AppDir, [string] $CurrentDir) {
    if (!(Test-Path $AppDir) -or !(Test-Path $CurrentDir)) {
        return $null
    }

    $currentFull = (Get-Item -LiteralPath $CurrentDir -Force).FullName.TrimEnd('\')
    $links = Get-ChildItem -LiteralPath $AppDir -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer -and $_.Name -ne 'current' -and -not [String]::IsNullOrEmpty($_.LinkType) }

    foreach ($link in $links) {
        $target = $link.Target
        if ($target -is [array]) {
            $target = $target[0]
        }
        if ([String]::IsNullOrEmpty($target)) {
            continue
        }
        try {
            $targetFull = (Get-Item -LiteralPath $target -Force -ErrorAction Stop).FullName.TrimEnd('\')
        } catch {
            $targetFull = $target.TrimEnd('\')
        }
        if ($targetFull -ieq $currentFull) {
            return $link.Name
        }
    }

    return $null
}
function Get-CurrentVersionFromManifest([string] $CurrentDir) {
    $manifestPath = Join-Path $CurrentDir 'manifest.json'
    if (Test-Path $manifestPath) {
        $m = parse_json $manifestPath
        if ($m -and $m.version) {
            return $m.version
        }
    }
    return $null
}
function Get-AppDirForCurrentOps([string] $Path) {
    # Accept both app directory and version directory as input.
    # If '<path>\current' exists, treat '<path>' as app directory.
    $current = Join-Path $Path 'current'
    if (Test-Path $current) {
        return $Path
    }
    return (Split-Path $Path)
}

# Creates or updates the "current" pointer for an app.
#
# Default layout:
#   <app>\current  -> (junction) <app>\<version>
#
# When config 'reverse_junction' is enabled:
#   <app>\current  -> (directory)
#   <app>\<version> -> (junction) <app>\current
#
# Returns the directory used for shims/shortcuts/env (usually '<app>\current').
function link_current($versiondir) {
    if (get_config NO_JUNCTION) { return $versiondir.ToString() }

    $reverse = get_config REVERSE_JUNCTION $false

    $versiondir = $versiondir.ToString()
    $appdir = Split-Path $versiondir
    $version = Split-Path $versiondir -Leaf
    $currentdir = Join-Path $appdir 'current'

    if ($currentdir -eq $versiondir) {
        abort "Error: Version 'current' is not allowed!"
    }

    if ($reverse) {
        Write-Host "Linking (reverse) $(friendly_path $versiondir) => $(friendly_path $currentdir)"

        # If the requested version is already the active one (version junction -> current dir), just return.
        $verTarget = Get-DirectoryLinkTarget $versiondir
        if ($verTarget -and (Test-Path $currentdir) -and [String]::IsNullOrEmpty((Get-DirectoryLinkType $currentdir))) {
            try {
                $currFull = (Get-Item -LiteralPath $currentdir -Force -ErrorAction Stop).FullName.TrimEnd('\')
                $verTFull = (Get-Item -LiteralPath $verTarget -Force -ErrorAction Stop).FullName.TrimEnd('\')
                if ($verTFull -ieq $currFull) {
                    return $currentdir
                }
            } catch {
                # ignore and continue with migration logic
            }
        }

        # Ensure the version path is not a link (we need to rename it later)
        if ((Test-Path $versiondir) -and -not [String]::IsNullOrEmpty((Get-DirectoryLinkType $versiondir))) {
            Remove-DirectoryLink $versiondir | Out-Null
        }

        # If current exists:
        # - remove it when it's a link (forward layout)
        # - otherwise preserve it by moving it back to the active version directory
        if (Test-Path $currentdir) {
            if (-not [String]::IsNullOrEmpty((Get-DirectoryLinkType $currentdir))) {
                Remove-DirectoryLink $currentdir | Out-Null
            } else {
                $oldVersion = Find-ActiveVersionFromReverseLayout $appdir $currentdir
                if (!$oldVersion) {
                    $oldVersion = Get-CurrentVersionFromManifest $currentdir
                }

                if ($oldVersion) {
                    $oldLink = Join-Path $appdir $oldVersion
                    if ((Test-Path $oldLink) -and -not [String]::IsNullOrEmpty((Get-DirectoryLinkType $oldLink))) {
                        Remove-DirectoryLink $oldLink | Out-Null
                    }

                    $dest = Join-Path $appdir $oldVersion
                    if (($oldVersion -eq $version) -or (Test-Path $dest)) {
                        $dest = Get-UniqueDirectoryPath (Join-Path $appdir "_$oldVersion.old")
                    }
                } else {
                    $dest = Get-UniqueDirectoryPath (Join-Path $appdir '_current.old')
                }

                Move-Item -LiteralPath $currentdir -Destination $dest -Force
            }
        }

        if (!(Test-Path $versiondir)) {
            abort "Error: Version directory '$(friendly_path $versiondir)' is missing."
        }

        # Move the requested version directory to 'current'
        Move-Item -LiteralPath $versiondir -Destination $currentdir -Force

        # Create version junction -> current directory
        New-DirectoryJunction $versiondir $currentdir | Out-Null
        attrib $versiondir +R /L

        return $currentdir
    } else {
        Write-Host "Linking $(friendly_path $currentdir) => $(friendly_path $versiondir)"

        # If current exists and is a directory (reverse layout), move it back to the active version directory first.
        if ((Test-Path $currentdir) -and [String]::IsNullOrEmpty((Get-DirectoryLinkType $currentdir))) {
            $oldVersion = Find-ActiveVersionFromReverseLayout $appdir $currentdir
            if (!$oldVersion) {
                $oldVersion = Get-CurrentVersionFromManifest $currentdir
            }

            if ($oldVersion) {
                $oldLink = Join-Path $appdir $oldVersion
                if ((Test-Path $oldLink) -and -not [String]::IsNullOrEmpty((Get-DirectoryLinkType $oldLink))) {
                    Remove-DirectoryLink $oldLink | Out-Null
                }

                $dest = Join-Path $appdir $oldVersion
                if (Test-Path $dest) {
                    $dest = Get-UniqueDirectoryPath (Join-Path $appdir "_$oldVersion.old")
                }
            } else {
                $dest = Get-UniqueDirectoryPath (Join-Path $appdir '_current.old')
            }

            Move-Item -LiteralPath $currentdir -Destination $dest -Force
        }

        if (Test-Path $currentdir) {
            # remove the junction
            if (-not [String]::IsNullOrEmpty((Get-DirectoryLinkType $currentdir))) {
                Remove-DirectoryLink $currentdir | Out-Null
            } else {
                # directory already handled above; but keep it safe
                Remove-Item -LiteralPath $currentdir -Recurse -Force -ErrorAction Stop
            }
        }

        # Ensure we point current to a real version directory (not a link)
        if ((Test-Path $versiondir) -and -not [String]::IsNullOrEmpty((Get-DirectoryLinkType $versiondir))) {
            abort "Error: Version directory '$(friendly_path $versiondir)' is a link. Please run 'scoop reset $version' to repair."
        }

        New-DirectoryJunction $currentdir $versiondir | Out-Null
        attrib $currentdir +R /L
        return $currentdir
    }
}

# Removes the directory junction for [app]/current which
# points to the current version directory for the app.
#
# Returns the 'current' junction directory (if it exists),
# otherwise the normal version directory.
function unlink_current($versiondir) {
    if (get_config NO_JUNCTION) { return $versiondir.ToString() }

    $versiondir = $versiondir.ToString()
    $appdir = Get-AppDirForCurrentOps $versiondir
    $currentdir = Join-Path $appdir 'current'

    if (Test-Path $currentdir) {
        Write-Host "Unlinking $(friendly_path $currentdir)"

        # Only remove the link if 'current' is a link. In reverse_junction layout 'current' is a directory.
        if (-not [String]::IsNullOrEmpty((Get-DirectoryLinkType $currentdir))) {
            Remove-DirectoryLink $currentdir | Out-Null
        }
        return $currentdir
    }

    return $versiondir
}

# to undo after installers add to path so that scoop manifest can keep track of this instead
function ensure_install_dir_not_in_path($dir, $global) {
    $path = (Get-EnvVar -Name 'PATH' -Global:$global)

    $fixed, $removed = find_dir_or_subdir $path "$dir"
    if ($removed) {
        $removed | ForEach-Object { "Installer added '$(friendly_path $_)' to path. Removing." }
        Set-EnvVar -Name 'PATH' -Value $fixed -Global:$global
    }

    if (!$global) {
        $fixed, $removed = find_dir_or_subdir (Get-EnvVar -Name 'PATH' -Global) "$dir"
        if ($removed) {
            $removed | ForEach-Object { warn "Installer added '$_' to system path. You might want to remove this manually (requires admin permission)." }
        }
    }
}

function find_dir_or_subdir($path, $dir) {
    $dir = $dir.trimend('\')
    $fixed = @()
    $removed = @()
    $path.split(';') | ForEach-Object {
        if ($_) {
            if (($_ -eq $dir) -or ($_ -like "$dir\*")) { $removed += $_ }
            else { $fixed += $_ }
        }
    }
    return [string]::join(';', $fixed), $removed
}

function env_add_path($manifest, $dir, $global, $arch) {
    $env_add_path = arch_specific 'env_add_path' $manifest $arch
    $dir = $dir.TrimEnd('\')
    if ($env_add_path) {
        if (get_config USE_ISOLATED_PATH) {
            Add-Path -Path ('%' + $scoopPathEnvVar + '%') -Global:$global
        }
        $path = $env_add_path.Where({ $_ }).ForEach({ Join-Path $dir $_ | Get-AbsolutePath }).Where({ is_in_dir $dir $_ })
        Add-Path -Path $path -TargetEnvVar $scoopPathEnvVar -Global:$global -Force
    }
}

function env_rm_path($manifest, $dir, $global, $arch) {
    $env_add_path = arch_specific 'env_add_path' $manifest $arch
    $dir = $dir.TrimEnd('\')
    if ($env_add_path) {
        $path = $env_add_path.Where({ $_ }).ForEach({ Join-Path $dir $_ | Get-AbsolutePath }).Where({ is_in_dir $dir $_ })
        Remove-Path -Path $path -Global:$global # TODO: Remove after forced isolating Scoop path
        Remove-Path -Path $path -TargetEnvVar $scoopPathEnvVar -Global:$global
    }
}

function env_set($manifest, $global, $arch) {
    $env_set = arch_specific 'env_set' $manifest $arch
    if ($env_set) {
        $env_set | Get-Member -MemberType NoteProperty | ForEach-Object {
            $name = $_.Name
            $val = $ExecutionContext.InvokeCommand.ExpandString($env_set.$($name))
            Set-EnvVar -Name $name -Value $val -Global:$global
            Set-Content env:\$name $val
        }
    }
}
function env_rm($manifest, $global, $arch) {
    $env_set = arch_specific 'env_set' $manifest $arch
    if ($env_set) {
        $env_set | Get-Member -MemberType NoteProperty | ForEach-Object {
            $name = $_.Name
            Set-EnvVar -Name $name -Value $null -Global:$global
            if (Test-Path env:\$name) { Remove-Item env:\$name }
        }
    }
}

function show_notes($manifest, $dir, $original_dir, $persist_dir) {
    if ($manifest.notes) {
        Write-Output 'Notes'
        Write-Output '-----'
        Write-Output (wraptext (substitute $manifest.notes @{ '$dir' = $dir; '$original_dir' = $original_dir; '$persist_dir' = $persist_dir }))
    }
}

function all_installed($apps, $global) {
    $apps | Where-Object {
        $app, $null, $null = parse_app $_
        installed $app $global
    }
}

# returns (uninstalled, installed)
function prune_installed($apps, $global) {
    $installed = @(all_installed $apps $global)

    $uninstalled = $apps | Where-Object { $installed -notcontains $_ }

    return @($uninstalled), @($installed)
}

function ensure_none_failed($apps) {
    foreach ($app in $apps) {
        $app = ($app -split '/|\\')[-1] -replace '\.json$', ''
        foreach ($global in $true, $false) {
            if ($global) {
                $instArgs = @('--global')
            } else {
                $instArgs = @()
            }
            if (failed $app $global) {
                if (installed $app $global) {
                    info "Repair previous failed installation of $app."
                    & "$PSScriptRoot\..\libexec\scoop-reset.ps1" $app @instArgs
                } else {
                    warn "Purging previous failed installation of $app."
                    & "$PSScriptRoot\..\libexec\scoop-uninstall.ps1" $app @instArgs
                }
            }
        }
    }
}

function show_suggestions($suggested) {
    $installed_apps = (installed_apps $true) + (installed_apps $false)

    foreach ($app in $suggested.keys) {
        $features = $suggested[$app] | Get-Member -type noteproperty | ForEach-Object { $_.name }
        foreach ($feature in $features) {
            $feature_suggestions = $suggested[$app].$feature

            $fulfilled = $false
            foreach ($suggestion in $feature_suggestions) {
                $suggested_app, $bucket, $null = parse_app $suggestion

                if ($installed_apps -contains $suggested_app) {
                    $fulfilled = $true
                    break
                }
            }

            if (!$fulfilled) {
                Write-Host "'$app' suggests installing '$([string]::join("' or '", $feature_suggestions))'."
            }
        }
    }
}

# Persistent data
function persist_def($persist) {
    if ($persist -is [Array]) {
        $source = $persist[0]
        $target = $persist[1]
    } else {
        $source = $persist
        $target = $null
    }

    if (!$target) {
        $target = $source
    }

    return $source, $target
}

function persist_data($manifest, $original_dir, $persist_dir) {
    $persist = $manifest.persist
    if ($persist) {
        $persist_dir = ensure $persist_dir

        if ($persist -is [String]) {
            $persist = @($persist)
        }

        $persist | ForEach-Object {
            $source, $target = persist_def $_

            Write-Host "Persisting $source"

            $source = $source.TrimEnd('/').TrimEnd('\\')

            $source = "$dir\$source"
            $target = "$persist_dir\$target"

            # if we have had persist data in the store, just create link and go
            if (Test-Path $target) {
                # if there is also a source data, rename it (to keep a original backup)
                if (Test-Path $source) {
                    Move-Item -Force $source "$source.original"
                }
                # we don't have persist data in the store, move the source to target, then create link
            } elseif (Test-Path $source) {
                # ensure target parent folder exist
                ensure (Split-Path -Path $target) | Out-Null
                Move-Item $source $target
                # we don't have neither source nor target data! we need to create an empty target,
                # but we can't make a judgement that the data should be a file or directory...
                # so we create a directory by default. to avoid this, use pre_install
                # to create the source file before persisting (DON'T use post_install)
            } else {
                $target = New-Object System.IO.DirectoryInfo($target)
                ensure $target | Out-Null
            }

            # create link
            if (is_directory $target) {
                # target is a directory, create junction
                New-DirectoryJunction $source $target | Out-Null
                attrib $source +R /L
            } else {
                # target is a file, create hard link
                New-Item -Path $source -ItemType HardLink -Value $target | Out-Null
            }
        }
    }
}

function unlink_persist_data($manifest, $dir) {
    $persist = $manifest.persist
    # unlink all junction / hard link in the directory
    if ($persist) {
        @($persist) | ForEach-Object {
            $source, $null = persist_def $_
            $source = Get-Item "$dir\$source" -ErrorAction SilentlyContinue
            if ($source.LinkType) {
                $source_path = $source.FullName
                # directory (junction)
                if ($source -is [System.IO.DirectoryInfo]) {
                    # remove read-only attribute on the link
                    attrib -R /L $source_path
                    # remove the junction
                    Remove-Item -Path $source_path -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    # remove the hard link
                    Remove-Item -Path $source_path -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# check whether write permission for Users usergroup is set to global persist dir, if not then set
function persist_permission($manifest, $global) {
    if ($global -and $manifest.persist -and (is_admin)) {
        $path = persistdir $null $global
        $user = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
        $target_rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'Write', 'ObjectInherit', 'none', 'Allow')
        $acl = Get-Acl -Path $path
        $acl.SetAccessRule($target_rule)
        $acl | Set-Acl -Path $path
    }
}

# test if there are running processes
function test_running_process($app, $global) {
    $processdir = appdir $app $global | Convert-Path
    $running_processes = Get-Process | Where-Object { $_.Path -like "$processdir\*" } | Out-String

    if ($running_processes) {
        if (get_config IGNORE_RUNNING_PROCESSES) {
            warn "The following instances of `"$app`" are still running. Scoop is configured to ignore this condition."
            Write-Host $running_processes
            return $false
        } else {
            error "The following instances of `"$app`" are still running. Close them and try again."
            Write-Host $running_processes
            return $true
        }
    } else {
        return $false
    }
}

# wrapper function to create junction links
# Required to handle docker/for-win#12240
function New-DirectoryJunction($source, $target) {
    # test if this script is being executed inside a docker container
    if (Get-Service -Name cexecsvc -ErrorAction SilentlyContinue) {
        cmd.exe /d /c "mklink /j `"$source`" `"$target`""
    } else {
        New-Item -Path $source -ItemType Junction -Value $target
    }
}
