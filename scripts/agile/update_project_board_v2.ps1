$ProjectId = "PVT_kwHOD4fhTM4BU152"

# Field IDs
$SizeFieldId = "PVTSSF_lAHOD4fhTM4BU152zhFK43k"
$EstimateFieldId = "PVTF_lAHOD4fhTM4BU152zhFK43w"

# Option IDs
$SizeXS = "911790be"
$SizeS  = "b277fb01"
$SizeM  = "86db8eb3"
$SizeL  = "853c8207"

# Item IDs
$Item1  = "PVTI_lAHOD4fhTM4BU152zgqK1tc"
$Item8  = "PVTI_lAHOD4fhTM4BU152zgqK1ts"
$Item10 = "PVTI_lAHOD4fhTM4BU152zgqK1uI"
$Item12 = "PVTI_lAHOD4fhTM4BU152zgqK1uU"
$Item14 = "PVTI_lAHOD4fhTM4BU152zgqK1uc"
$Item16 = "PVTI_lAHOD4fhTM4BU152zgqK1uw"
$Item18 = "PVTI_lAHOD4fhTM4BU152zgqK1u8"

Write-Host "Updating Project Board fields for Size and Estimate..."

# Issue 1 - Size M, Est 3
gh project item-edit --id $Item1 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeM
gh project item-edit --id $Item1 --project-id $ProjectId --field-id $EstimateFieldId --number 3

# Issue 8 - Size XS, Est 1
gh project item-edit --id $Item8 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeXS
gh project item-edit --id $Item8 --project-id $ProjectId --field-id $EstimateFieldId --number 1

# Issue 10 - Size S, Est 2
gh project item-edit --id $Item10 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeS
gh project item-edit --id $Item10 --project-id $ProjectId --field-id $EstimateFieldId --number 2

# Issue 12 - Size XS, Est 1
gh project item-edit --id $Item12 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeXS
gh project item-edit --id $Item12 --project-id $ProjectId --field-id $EstimateFieldId --number 1

# Issue 14 - Size M, Est 3
gh project item-edit --id $Item14 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeM
gh project item-edit --id $Item14 --project-id $ProjectId --field-id $EstimateFieldId --number 3

# Issue 16 - Size S, Est 2
gh project item-edit --id $Item16 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeS
gh project item-edit --id $Item16 --project-id $ProjectId --field-id $EstimateFieldId --number 2

# Issue 18 - Size L, Est 5
gh project item-edit --id $Item18 --project-id $ProjectId --field-id $SizeFieldId --single-select-option-id $SizeL
gh project item-edit --id $Item18 --project-id $ProjectId --field-id $EstimateFieldId --number 5

Write-Host "Project Board updates via GraphQL metadata fully complete!"
