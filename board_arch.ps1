$ProjectId = "PVT_kwHOD4fhTM4BU152"
$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$DoneOptionId = "98236657"
$InReviewOptionId = "aba860b9"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"
$Iteration1Id = "381c7c80"

# Issue #40
$IssueItemId = "PVTI_lAHOD4fhTM4BU152zgrZoJ0"
gh project item-edit --id $IssueItemId --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $DoneOptionId
gh project item-edit --id $IssueItemId --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

# PR #41
$PRItemId = "PVTI_lAHOD4fhTM4BU152zgrZuZA"
gh project item-edit --id $PRItemId --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $InReviewOptionId
gh project item-edit --id $PRItemId --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

# Close issue #40
gh issue close 40 --repo sterlinggarnett/cis3353_s26_TL_SG_MF

Write-Host "Issue #40 marked Done. PR #41 marked In Review. Both in Iteration 1."
