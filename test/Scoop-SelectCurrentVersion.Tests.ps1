BeforeAll {
    . "$PSScriptRoot\Scoop-TestLib.ps1"
    . "$PSScriptRoot\..\lib\manifest.ps1"  # parse_json
    . "$PSScriptRoot\..\lib\versions.ps1"
}

Describe 'Select-CurrentVersion' -Tag 'Scoop', 'Windows' {
    BeforeAll {
        function get_config {
            param($name, $default)
            # Only NO_JUNCTION is relevant here
            return $false
        }
    }

    It 'detects nightly version in forward layout (current junction -> nightly-YYYYMMDD dir)' {
        $script:appDir = Join-Path $TestDrive 'apps\nightlyfwd'
        function appdir { param($AppName, $Global) return $script:appDir }

        $nightly = 'nightly-20260104'
        $versionDir = Join-Path $script:appDir $nightly
        $currentDir = Join-Path $script:appDir 'current'

        New-Item -ItemType Directory -Path $versionDir | Out-Null
        @{ version = 'nightly' } | ConvertTo-Json | Set-Content -Path (Join-Path $versionDir 'manifest.json') -Encoding UTF8
        New-Item -Path $currentDir -ItemType Junction -Value $versionDir | Out-Null

        Select-CurrentVersion -AppName 'nightlyfwd' | Should -Be $nightly
    }

    It 'detects nightly version in reverse layout (nightly-YYYYMMDD junction -> current dir)' {
        $script:appDir = Join-Path $TestDrive 'apps\nightlyrev'
        function appdir { param($AppName, $Global) return $script:appDir }

        $nightly = 'nightly-20260104'
        $versionJunction = Join-Path $script:appDir $nightly
        $currentDir = Join-Path $script:appDir 'current'

        New-Item -ItemType Directory -Path $currentDir | Out-Null
        @{ version = 'nightly' } | ConvertTo-Json | Set-Content -Path (Join-Path $currentDir 'manifest.json') -Encoding UTF8
        New-Item -Path $versionJunction -ItemType Junction -Value $currentDir | Out-Null

        Select-CurrentVersion -AppName 'nightlyrev' | Should -Be $nightly
    }
}


