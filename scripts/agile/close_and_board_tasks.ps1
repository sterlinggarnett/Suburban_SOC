$repo = "sterlinggarnett/cis3353_s26_TL_SG_MF"
$base = "https://github.com/$repo/issues"
$ProjectId = "PVT_kwHOD4fhTM4BU152"
$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$DoneOptionId = "98236657"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"
$Iteration1Id = "381c7c80"

$issues = @(29, 30, 31, 32, 33, 34, 35, 36, 37)

foreach ($num in $issues) {
    $url = "$base/$num"
    Write-Host "Adding issue #$num to project board..."
    $result = gh project item-add 4 --owner sterlinggarnett --url $url --format json | ConvertFrom-Json
    $itemId = $result.id

    Write-Host "  Setting Status=Done for #$num..."
    gh project item-edit --id $itemId --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $DoneOptionId

    Write-Host "  Setting Iteration=1 for #$num..."
    gh project item-edit --id $itemId --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

    Write-Host "  Closing issue #$num..."
    gh issue close $num --repo $repo
}

Write-Host "All done! Issues added to board, marked Done, and closed."
