$ProjectId = "PVT_kwHOD4fhTM4BU152"

$StatusFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFKt6M"
$IterationFieldId = "PVTIF_lAHOD4fhTM4BU152zhFK44Q"

$BacklogOptionId = "f75ad846"
$Iteration1Id = "381c7c80"

$Items = @(
    "PVTI_lAHOD4fhTM4BU152zgqK1tc",
    "PVTI_lAHOD4fhTM4BU152zgqK1ts",
    "PVTI_lAHOD4fhTM4BU152zgqK1uI",
    "PVTI_lAHOD4fhTM4BU152zgqK1uU",
    "PVTI_lAHOD4fhTM4BU152zgqK1uc",
    "PVTI_lAHOD4fhTM4BU152zgqK1uw",
    "PVTI_lAHOD4fhTM4BU152zgqK1u8",
    "PVTI_lAHOD4fhTM4BU152zgqfrNk",
    "PVTI_lAHOD4fhTM4BU152zgqfrOQ",
    "PVTI_lAHOD4fhTM4BU152zgqfrO0",
    "PVTI_lAHOD4fhTM4BU152zgqfrYE"
)

Write-Host "Updating Project Board Status and Iterations..."

foreach ($Item in $Items) {
    gh project item-edit --id $Item --project-id $ProjectId --field-id $StatusFieldId --single-select-option-id $BacklogOptionId
    gh project item-edit --id $Item --project-id $ProjectId --field-id $IterationFieldId --iteration-id $Iteration1Id
}

Write-Host "All items have been mapped to Backlog and Iteration 1!"
