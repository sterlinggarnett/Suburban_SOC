$ProjectId = "PVT_kwHOD4fhTM4BU152"

# Field IDs
$SizeFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFK43k"
$EstimateFieldId = "PVTF_lAHOD4fhTM4BU152zhFK43w"

# Option IDs
$SizeM  = "86db8eb3"
$SizeL  = "853c8207"

$Item20 = "PVTI_lAHOD4fhTM4BU152zgqfrNk"
$Item21 = "PVTI_lAHOD4fhTM4BU152zgqfrOQ"
$Item23 = "PVTI_lAHOD4fhTM4BU152zgqfrYE"
$Item22 = "PVTI_lAHOD4fhTM4BU152zgqfrO0"

Write-Host "Updating Size and Estimates..."
# Issue 20
gh project item-edit --id $Item20 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeM
gh project item-edit --id $Item20 --project-id $ProjectId --field-id $EstimateFieldId --number 3

# Issue 21
gh project item-edit --id $Item21 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeM
gh project item-edit --id $Item21 --project-id $ProjectId --field-id $EstimateFieldId --number 3

# Issue 23
gh project item-edit --id $Item23 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeM
gh project item-edit --id $Item23 --project-id $ProjectId --field-id $EstimateFieldId --number 3

# Issue 22
gh project item-edit --id $Item22 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeL
gh project item-edit --id $Item22 --project-id $ProjectId --field-id $EstimateFieldId --number 5

Write-Host "Agile estimations synced to the project board."
