$ProjectId = "PVT_kwHOD4fhTM4BU152"
$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$DoneOptionId = "98236657"
$InReviewOptionId = "aba860b9"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"
$Iteration1Id = "381c7c80"

$Issue44 = gh project item-add 4 --owner sterlinggarnett --url https://github.com/sterlinggarnett/cis3353_s26_TL_SG_MF/issues/44 --format json | ConvertFrom-Json
$PR45    = gh project item-add 4 --owner sterlinggarnett --url https://github.com/sterlinggarnett/cis3353_s26_TL_SG_MF/pull/45  --format json | ConvertFrom-Json

gh project item-edit --id $Issue44.id --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $DoneOptionId
gh project item-edit --id $Issue44.id --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

gh project item-edit --id $PR45.id --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $InReviewOptionId
gh project item-edit --id $PR45.id --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

gh issue close 44 --repo sterlinggarnett/cis3353_s26_TL_SG_MF

Write-Host "Issue #44 Done. PR #45 In Review. Both Iteration 1."
