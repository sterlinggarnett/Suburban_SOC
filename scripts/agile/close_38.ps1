$ProjectId = "PVT_kwHOD4fhTM4BU152"
$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$DoneOptionId = "98236657"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"
$Iteration1Id = "381c7c80"

$ItemId = "PVTI_lAHOD4fhTM4BU152zgrZRRA"

gh project item-edit --id $ItemId --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $DoneOptionId
gh project item-edit --id $ItemId --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id
gh issue close 38 --repo sterlinggarnett/cis3353_s26_TL_SG_MF

Write-Host "Issue #38 marked Done on board and closed."
