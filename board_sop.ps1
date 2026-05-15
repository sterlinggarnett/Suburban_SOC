$ProjectId = "PVT_kwHOD4fhTM4BU152"
$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$DoneOptionId = "98236657"
$InReviewOptionId = "aba860b9"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"
$Iteration1Id = "381c7c80"

# Issue #42
gh project item-edit --id "PVTI_lAHOD4fhTM4BU152zgrZzXg" --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $DoneOptionId
gh project item-edit --id "PVTI_lAHOD4fhTM4BU152zgrZzXg" --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

# PR #43
gh project item-edit --id "PVTI_lAHOD4fhTM4BU152zgrZ0G0" --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $InReviewOptionId
gh project item-edit --id "PVTI_lAHOD4fhTM4BU152zgrZ0G0" --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

gh issue close 42 --repo sterlinggarnett/cis3353_s26_TL_SG_MF

Write-Host "Issue #42 Done. PR #43 In Review. Both in Iteration 1."
