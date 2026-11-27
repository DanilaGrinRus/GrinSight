$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
Add-Type -AssemblyName System.Windows.Forms
$saving = $env:GRINSIGHT_CHECKPOINT_ACTION -eq 'save'
$dialog = if ($saving) { New-Object System.Windows.Forms.SaveFileDialog } else { New-Object System.Windows.Forms.OpenFileDialog }
try {
    $dialog.RestoreDirectory = $true
    $dialog.Title = $env:GRINSIGHT_POINT_TITLE
    if ($saving) {
        $dialog.Filter = 'GSHP (*.gshp)|*.gshp'
        $dialog.DefaultExt = 'gshp'
        $dialog.FileName = 'GrinSight.gshp'
        $dialog.OverwritePrompt = $false
    } else {
        $dialog.CheckFileExists = $true
        $dialog.Filter = 'GSHP / JSON (*.gshp, *.json)|*.gshp;*.json|*.*|*.*'
    }
    if ($dialog.ShowDialog() -ne 'OK') { [Console]::Write('null'); return }
    [Console]::Write((ConvertTo-Json -Compress -InputObject $dialog.FileName))
} finally {
    $dialog.Dispose()
}
