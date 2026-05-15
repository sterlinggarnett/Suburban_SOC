$ProjectId = "PVT_kwHOD4fhTM4BU152"
$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$InReviewOptionId = "aba860b9"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"
$Iteration1Id = "381c7c80"

# PR item ID
$PRItemId = "PVTI_lAHOD4fhTM4BU152zgrZS-4"

gh project item-edit --id $PRItemId --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $InReviewOptionId
gh project item-edit --id $PRItemId --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id

Write-Host "PR #39 added to project board under In Review / Iteration 1."
