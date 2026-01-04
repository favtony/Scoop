BeforeAll {
    . "$PSScriptRoot\Scoop-TestLib.ps1"
    . "$PSScriptRoot\..\lib\core.ps1"
    . "$PSScriptRoot\..\lib\manifest.ps1"
    . "$PSScriptRoot\..\lib\install.ps1"
}

Describe 'reverse_junction layout' -Tag 'Scoop', 'Windows' {
    AfterAll {
        # Clean up junctions with read-only attributes; otherwise Pester may fail to remove $TestDrive.
        $appsRoot = Join-Path $TestDrive 'apps'
        if (Test-Path $appsRoot) {
            Get-ChildItem -LiteralPath $appsRoot -Recurse -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if (-not [String]::IsNullOrEmpty($_.LinkType)) {
                    attrib $_.FullName -R /L | Out-Null
                }
            }
            Remove-Item -LiteralPath $appsRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'link_current' {
        It 'creates current as a directory and version as a junction when reverse_junction is enabled' {
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $true }
                return $default
            }

            $appdir = Join-Path $TestDrive 'apps\foo'
            $version = '1.0.0'
            $versiondir = Join-Path $appdir $version
            $currentdir = Join-Path $appdir 'current'

            New-Item -ItemType Directory -Path $versiondir | Out-Null
            'a' | Set-Content -Path (Join-Path $versiondir 'a.txt') -Encoding Ascii

            $ret = link_current $versiondir
            $ret | Should -Be $currentdir

            (Test-Path $currentdir) | Should -BeTrue
            $currentItem = Get-Item -LiteralPath $currentdir -Force
            $currentItem.LinkType | Should -BeNullOrEmpty

            (Test-Path $versiondir) | Should -BeTrue
            $verItem = Get-Item -LiteralPath $versiondir -Force
            $verItem.LinkType | Should -Not -BeNullOrEmpty

            (Join-Path $currentdir 'a.txt') | Should -Exist
            (Join-Path $versiondir 'a.txt') | Should -Exist
        }

        It 'creates current as a junction to the version directory when reverse_junction is disabled' {
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $false }
                return $default
            }

            $appdir = Join-Path $TestDrive 'apps\bar'
            $version = '2.0.0'
            $versiondir = Join-Path $appdir $version
            $currentdir = Join-Path $appdir 'current'

            New-Item -ItemType Directory -Path $versiondir | Out-Null
            'b' | Set-Content -Path (Join-Path $versiondir 'b.txt') -Encoding Ascii

            $ret = link_current $versiondir
            $ret | Should -Be $currentdir

            (Test-Path $currentdir) | Should -BeTrue
            $currentItem = Get-Item -LiteralPath $currentdir -Force
            $currentItem.LinkType | Should -Not -BeNullOrEmpty

            (Join-Path $currentdir 'b.txt') | Should -Exist
            (Join-Path $versiondir 'b.txt') | Should -Exist
        }

        It 'migrates from forward layout to reverse layout when toggled' {
            $appdir = Join-Path $TestDrive 'apps\baz'
            $versionA = '1.0.0'
            $versionB = '1.1.0'
            $dirA = Join-Path $appdir $versionA
            $dirB = Join-Path $appdir $versionB
            $currentdir = Join-Path $appdir 'current'

            # forward layout for versionA
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $false }
                return $default
            }
            New-Item -ItemType Directory -Path $dirA | Out-Null
            'A' | Set-Content -Path (Join-Path $dirA 'ver.txt') -Encoding Ascii
            link_current $dirA | Out-Null
            (Get-Item -LiteralPath $currentdir -Force).LinkType | Should -Not -BeNullOrEmpty

            # simulate install of versionB
            New-Item -ItemType Directory -Path $dirB | Out-Null
            'B' | Set-Content -Path (Join-Path $dirB 'ver.txt') -Encoding Ascii

            # toggle to reverse layout
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $true }
                return $default
            }

            link_current $dirB | Out-Null

            $currentItem = Get-Item -LiteralPath $currentdir -Force
            $currentItem.LinkType | Should -BeNullOrEmpty

            # versionB becomes junction to current
            $verBItem = Get-Item -LiteralPath $dirB -Force
            $verBItem.LinkType | Should -Not -BeNullOrEmpty
            (Join-Path $currentdir 'ver.txt') | Should -FileContentMatch '^B$'

            # versionA stays as a directory with its content
            $verAItem = Get-Item -LiteralPath $dirA -Force
            $verAItem.LinkType | Should -BeNullOrEmpty
            (Join-Path $dirA 'ver.txt') | Should -FileContentMatch '^A$'
        }

        It 'migrates from reverse layout to forward layout when toggled (reset-like)' {
            $appdir = Join-Path $TestDrive 'apps\qux'
            $versionA = '3.0.0'
            $versionB = '3.1.0'
            $dirA = Join-Path $appdir $versionA
            $dirB = Join-Path $appdir $versionB
            $currentdir = Join-Path $appdir 'current'

            # reverse layout for versionA
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $true }
                return $default
            }
            New-Item -ItemType Directory -Path $dirA | Out-Null
            'A' | Set-Content -Path (Join-Path $dirA 'ver.txt') -Encoding Ascii
            link_current $dirA | Out-Null

            # add an older version directory
            New-Item -ItemType Directory -Path $dirB | Out-Null
            'B' | Set-Content -Path (Join-Path $dirB 'ver.txt') -Encoding Ascii

            # toggle to forward layout, set current to versionB (reset-like)
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $false }
                return $default
            }
            link_current $dirB | Out-Null

            # current is a junction again, points to versionB
            $currentItem = Get-Item -LiteralPath $currentdir -Force
            $currentItem.LinkType | Should -Not -BeNullOrEmpty
            (Join-Path $currentdir 'ver.txt') | Should -FileContentMatch '^B$'

            # versionA should now be a directory (old current moved back)
            $verAItem = Get-Item -LiteralPath $dirA -Force
            $verAItem.LinkType | Should -BeNullOrEmpty
            (Join-Path $dirA 'ver.txt') | Should -FileContentMatch '^A$'
        }
    }

    Context 'unlink_current' {
        It 'removes current junction in forward layout, but keeps current directory in reverse layout' {
            $appdir = Join-Path $TestDrive 'apps\unlink'
            $version = '1.0.0'
            $versiondir = Join-Path $appdir $version
            $currentdir = Join-Path $appdir 'current'

            # forward
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $false }
                return $default
            }
            New-Item -ItemType Directory -Path $versiondir | Out-Null
            link_current $versiondir | Out-Null
            (Get-Item -LiteralPath $currentdir -Force).LinkType | Should -Not -BeNullOrEmpty

            unlink_current $versiondir | Should -Be $currentdir
            (Test-Path $currentdir) | Should -BeFalse

            # reverse
            Remove-Item -LiteralPath $appdir -Recurse -Force -ErrorAction SilentlyContinue
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                if ($n -eq 'reverse_junction') { return $true }
                return $default
            }
            New-Item -ItemType Directory -Path $versiondir | Out-Null
            link_current $versiondir | Out-Null
            (Get-Item -LiteralPath $currentdir -Force).LinkType | Should -BeNullOrEmpty

            unlink_current $versiondir | Should -Be $currentdir
            (Test-Path $currentdir) | Should -BeTrue
        }

        It 'accepts appdir as input (used by bin/uninstall.ps1)' {
            Mock get_config {
                param($name, $default)
                $n = $name.ToString().ToLowerInvariant()
                if ($n -eq 'no_junction') { return $false }
                return $default
            }

            $appdir = Join-Path $TestDrive 'apps\unlink2'
            $currentdir = Join-Path $appdir 'current'
            New-Item -ItemType Directory -Path $currentdir | Out-Null

            unlink_current $appdir | Should -Be $currentdir
        }
    }
}


