function Read-PublicStatus($window, $deadline, $progress, [int]$attempt = 0) {
    $button = [Windows.Automation.ControlType]::Button
    $invoke = [Windows.Automation.InvokePattern]::Pattern
    $start = [DateTime]::UtcNow
    $last = ''
    $heartbeat = [DateTime]::MinValue
    $header = $null
    $mark = ''
    $height = 0
    while ([DateTime]::UtcNow -lt $deadline) {
        $items = @(Children $window)
        foreach ($item in $items) {
            $c = $item.Current
            if ($c.ControlType -ne $button) { continue }
            $name = $c.Name
            if ($name -cnotmatch '^(VERIFIED|CHECKING|CATCHING UP|NO DATA|SEARCHING|NOT VERIFIED|ПРОВЕРЕНО|ПРОВЕРЯЕТСЯ|ДОГОНЯЕТ|ИДЁТ ПОИСК|НЕТ ДАННЫХ|НЕ ПРОВЕРЕНО)\s') { continue }
            $mark = $Matches[1]
            $elapsed = [int]([DateTime]::UtcNow - $start).TotalSeconds
            if ($last -ne $mark -or ([DateTime]::UtcNow - $heartbeat).TotalSeconds -ge 30) {
                [IO.File]::AppendAllText($progress, ((@{seconds=$elapsed;badge=$mark}|ConvertTo-Json -Compress) + [Environment]::NewLine))
                $last = $mark
                $heartbeat = [DateTime]::UtcNow
            }
            if ($mark -in @('VERIFIED','ПРОВЕРЕНО') -and $name -match '(?:at tip|на вершине|tip at block|вершину на блоке)\s+([0-9][0-9\s\u202f]*)') {
                $height = [int]($Matches[1] -replace '[^0-9]','')
                $header = $item
                break
            }
        }
        if ($null -ne $header) { break }
        Start-Sleep -Milliseconds 1200
    }
    if ($null -eq $header -or $height -le 4122000) { throw 'tip not visible' }
    $panel = $null
    if ($request.ready_pixels) {
        $panel = [ordered]@{stable=$false;modal_absent=$true;green_dot_pixels=0;green_text_pixels=0}
        foreach ($pass in 1,2) {
            $head = $false
            $row = $null
            foreach ($entry in (Children $window)) {
                $view = $entry.Current
                if ($view.Name -ceq 'Connection and synchronisation') { $head = $true }
                if ($head -and $view.Name -ceq 'Ready to use' -and -not $view.IsOffscreen) { $row = $view }
                if ($view.ControlType -eq $button -and $view.Name -in @('Close','OK','Done') -and -not $view.IsOffscreen -and $view.BoundingRectangle.Top -gt $window.Current.BoundingRectangle.Top + 45) { $panel.modal_absent = $false }
            }
            if (!$row) { break }
            if ($pass -eq 1) { Start-Sleep -Seconds 2 }
            else {
                $panel.stable = $true
                $b = $row.BoundingRectangle
                $bounds = @([int]$b.Left,[int]$b.Top,[int]$b.Right,[int]$b.Bottom)
                $startInfo = [Diagnostics.ProcessStartInfo]::new()
                $startInfo.FileName = $request.python
                $startInfo.Arguments = '"' + $request.ready_pixels + '" ' + $request.ui_pid + ' ' + $window.Current.NativeWindowHandle + ' ' + ($bounds -join ' ')
                $startInfo.UseShellExecute = $false
                $startInfo.CreateNoWindow = $true
                $startInfo.RedirectStandardOutput = $true
                $pixels = [Diagnostics.Process]::Start($startInfo)
                try {
                    $values = $pixels.StandardOutput.ReadToEnd()
                    $pixels.WaitForExit()
                    if ($pixels.ExitCode -ne 0) { throw 'ready colours could not be read' }
                    $colours = $values | ConvertFrom-Json
                    $panel.green_dot_pixels = $colours.green_dot_pixels
                    $panel.green_text_pixels = $colours.green_text_pixels
                } finally { $pixels.Dispose() }
            }
        }
        [IO.File]::AppendAllText($progress,(($panel|ConvertTo-Json -Compress)+[Environment]::NewLine))
    }
    if (!$request.inspect_details) {
        return [ordered]@{home=$mark; home_height=$height; details_checked=$false; details=$null;
            ready_explanation=($name -match 'ready to use|можно пользоваться'); ready_panel=$panel;
            seconds_since_home=[int]([DateTime]::UtcNow-$start).TotalSeconds}
    }
    $header.GetCurrentPattern($invoke).Invoke()
    $until = [DateTime]::UtcNow.AddSeconds(35)
    while ([DateTime]::UtcNow -lt $until) {
        $names = @(foreach ($item in (Children $window)) { $item.Current.Name })
        $titleIndex = [Array]::IndexOf($names, 'Details')
        if ($titleIndex -lt 0) { $titleIndex = [Array]::IndexOf($names, 'Подробнее') }
        if ($titleIndex -ge 0) {
            $currentHome = @($names | Select-Object -First $titleIndex | Where-Object {
                $_ -match '^(VERIFIED|ПРОВЕРЕНО)\s.+(?:at tip|на вершине|tip at block|вершину на блоке)\s+([0-9][0-9\s\u202f]*)'
            } | Select-Object -First 1)
            if ($currentHome.Count -eq 1 -and $currentHome[0] -match '^(VERIFIED|ПРОВЕРЕНО)\s.+(?:at tip|на вершине|tip at block|вершину на блоке)\s+([0-9][0-9\s\u202f]*)') {
                $mark = $Matches[1]; $height = [int]($Matches[2] -replace '[^0-9]','')
                $name = $currentHome[0]
            }
            $sheet = @($names | Select-Object -Skip ($titleIndex + 1))
            $details = @($sheet | Where-Object { $_ -ceq $mark })
            $detailsHeight = 0
            foreach ($text in $sheet) {
                if ($text -match '^(?:at the tip, block|на вершине, блок)\s+([0-9\s\u202f]+)$') {
                    $detailsHeight = [int]($Matches[1] -replace '[^0-9]','')
                    break
                }
            }
            $timeRow = @($sheet | Where-Object { $_ -match '^(confirmed by public nodes,|подтверждено публичными нодами,)' })
            $selectedHeight = 0
            for ($i = 0; $i -lt $sheet.Count - 1; $i++) {
                if ($sheet[$i] -notin @('Chosen tip','Выбранная вершина')) { continue }
                foreach ($value in @($sheet | Select-Object -Skip ($i+1) -First 3)) {
                    if ($value -match '^(?:block|блок)\s+([0-9\s\u202f]+)$') {
                        $selectedHeight = [int]($Matches[1] -replace '[^0-9]','')
                        break
                    }
                }
            }
            if ($details.Count -ge 1 -and $detailsHeight -eq $height -and $timeRow.Count -gt 0 -and $selectedHeight -eq $height) {
                $origin = @($sheet | Where-Object { $_ -match '^Release starting point\.|^Imported checkpoint at block |^Точка из выпуска\.|^Импортирована точка на блоке ' } | Select-Object -First 1)
                # A refresh may populate the history row after the tip is visible.
                if (!$origin -and [DateTime]::UtcNow -lt $until.AddSeconds(-10)) { Start-Sleep -Milliseconds 600; continue }
                return [ordered]@{home=$mark; details_checked=$true; details=$details[0]; home_height=$height; details_height=$detailsHeight;
                    starting_point_detail=($origin -join '');
                    ready_explanation=($name -match 'ready to use|можно пользоваться');
                    ready_panel=$panel;
                    independent_time=$true; selected_height=$selectedHeight;
                    seconds_since_home=[int]([DateTime]::UtcNow-$start).TotalSeconds}
            }
            if ($currentHome.Count -eq 0 -and $detailsHeight -gt $height -and $attempt -lt 3) {
                $close = @((Children $window) | Where-Object {
                    $_.Current.ControlType -eq $button -and $_.Current.Name -in @('Close','Закрыть')
                })
                if ($close.Count -eq 1) {
                    $close[0].GetCurrentPattern($invoke).Invoke()
                    [IO.File]::AppendAllText($progress, ((@{tip_advanced=@($height,$detailsHeight)}|ConvertTo-Json -Compress) + [Environment]::NewLine))
                    Start-Sleep -Milliseconds 400
                    return Read-PublicStatus $window $deadline $progress ($attempt + 1)
                }
            }
            $diag = [ordered]@{found_title=$true; badge_matches=$details.Count; wallet_height=$detailsHeight; home_height=$height; time_matches=$timeRow.Count; selected_height=$selectedHeight}
        }
        Start-Sleep -Milliseconds 250
    }
    [IO.File]::AppendAllText($progress, ((@{details_diagnostic=$diag}|ConvertTo-Json -Compress) + [Environment]::NewLine))
    throw 'details mismatch'
}
