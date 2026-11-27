$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$r = [Console]::In.ReadToEnd() | ConvertFrom-Json
$spec = $r.language_check
$ui = [Diagnostics.Process]::GetProcessById($r.ui_pid)
if ($ui.MainModule.FileName -ne $r.ui) { throw 'Unexpected window process' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -Namespace LangProbe -Name Window -MemberDefinition @'
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr win, out uint pid);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr win, uint msg, IntPtr wp, IntPtr lp);
[DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr win, IntPtr dst, uint flags);
'@
$end = [DateTime]::UtcNow.AddSeconds($r.timeout)
$result = [ordered]@{stage='chooser'; chooser=$false; login_translated=$false; recovery_example=$false; captured=$false}
$desktop = [Windows.Automation.AutomationElement]::RootElement
$condition = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty, [int]$r.ui_pid)
$win = $null
$handle = [IntPtr]::Zero
function Items($w) {
    $w.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
}
function WaitLabel([string]$label, [bool]$button) {
    $result.last_expected = $label
    while ([DateTime]::UtcNow -lt $end) {
        foreach ($item in (Items $win)) {
            if ($item.Current.Name -ceq $label -and (-not $button -or $item.Current.ControlType -eq [Windows.Automation.ControlType]::Button)) {
                return $item
            }
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'Missing expected translation'
}
function Press($item) {
    $item.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function SaveWindow($w, [string]$path) {
    $bounds = $w.Current.BoundingRectangle
    $bmp = [Drawing.Bitmap]::new([int]$bounds.Width,[int]$bounds.Height)
    try {
        $g = [Drawing.Graphics]::FromImage($bmp)
        try {
            $dc = $g.GetHdc()
            try { $ok = [LangProbe.Window]::PrintWindow($handle,$dc,2) }
            finally { $g.ReleaseHdc($dc) }
        } finally { $g.Dispose() }
        if (-not $ok) { throw 'Window capture failed' }
        $bmp.Save($path,[Drawing.Imaging.ImageFormat]::Png)
    } finally { $bmp.Dispose() }
}
try {
    while ([DateTime]::UtcNow -lt $end -and $null -eq $win) {
        foreach ($w in $desktop.FindAll([Windows.Automation.TreeScope]::Children,$condition)) {
            $buttons = @((Items $w) | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button })
            $names = @($buttons | ForEach-Object { $_.Current.Name })
            if (@('English','Русский','简体中文','한국어','日本語','Deutsch','Français' | Where-Object { $names -cnotcontains $_ }).Count -ne 0) { continue }
            $win = $w
            $handle = [IntPtr]$win.Current.NativeWindowHandle
            [uint32]$owner = 0
            if ([LangProbe.Window]::GetWindowThreadProcessId($handle,[ref]$owner) -eq 0 -or $owner -ne $ui.Id) { throw 'Unexpected window' }
            $result.chooser = $true
            $target = @($buttons | Where-Object { $_.Current.Name -ceq $spec.native })
            Press $target[0]
            break
        }
        if ($null -eq $win) { Start-Sleep -Milliseconds 200 }
    }
    if ($null -eq $win) { throw 'Chooser missing' }
    $result.stage = 'login-translations'
    $null = WaitLabel $spec.create $true
    $restore = WaitLabel $spec.restore $true
    $optionButtons = @((Items $win) | Where-Object {
        $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and
        $_.Current.Name -cin @($spec.options,$spec.hide_options)
    })
    if ($optionButtons.Count -ne 1) { throw 'Missing translated options button' }
    $result.login_translated = $true
    SaveWindow $win $spec.login_capture
    $result.stage = 'recovery-help'
    Press $restore
    $ask = WaitLabel ($spec.words + ' — ' + $spec.ask) $true
    Press $ask
    $null = WaitLabel $spec.example $false
    $result.recovery_example = $true
    Start-Sleep -Milliseconds 300
    SaveWindow $win $spec.help_capture
    $result.captured = $true
    $result.stage = 'accepted'
} catch {
    $result.failure = $_.Exception.GetBaseException().GetType().Name
    if ($null -ne $win) {
        # This test opens only an empty login or restoration form; never log edit controls.
        $result.visible_buttons = @((Items $win) | Where-Object {
            $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and -not $_.Current.IsOffscreen
        } | ForEach-Object { $_.Current.Name })
    }
} finally {
    if ($handle -ne [IntPtr]::Zero) {
        $result.close_requested = [LangProbe.Window]::PostMessage($handle,0x10,[IntPtr]::Zero,[IntPtr]::Zero)
    }
}
[Console]::WriteLine(($result | ConvertTo-Json -Compress))
