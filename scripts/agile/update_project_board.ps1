Write-Host "Adding Redirect Comments to Closed Task Issues..."
gh issue comment 7 --body "Closed in favor of formal parent User Story #8."
gh issue comment 9 --body "Closed in favor of formal parent User Story #10."
gh issue comment 11 --body "Closed in favor of formal parent User Story #12."
gh issue comment 13 --body "Closed in favor of formal parent User Story #14."
gh issue comment 15 --body "Closed in favor of formal parent User Story #16."
gh issue comment 17 --body "Closed in favor of formal parent User Story #18."

Write-Host "Updating Project Board fields for Size and Estimate..."

# Issue 1 - Size M, Est 3
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1tc" --field "Size" --single-select-option "M"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1tc" --field "Estimate" --number 3

# Issue 8 - Size XS, Est 1
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1ts" --field "Size" --single-select-option "XS"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1ts" --field "Estimate" --number 1

# Issue 10 - Size S, Est 2
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uI" --field "Size" --single-select-option "S"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uI" --field "Estimate" --number 2

# Issue 12 - Size XS, Est 1
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uU" --field "Size" --single-select-option "XS"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uU" --field "Estimate" --number 1

# Issue 14 - Size M, Est 3
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uc" --field "Size" --single-select-option "M"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uc" --field "Estimate" --number 3

# Issue 16 - Size S, Est 2
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uw" --field "Size" --single-select-option "S"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1uw" --field "Estimate" --number 2

# Issue 18 - Size L, Est 5
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1u8" --field "Size" --single-select-option "L"
gh project item-edit 4 --owner sterlinggarnett --id "PVTI_lAHOD4fhTM4BU152zgqK1u8" --field "Estimate" --number 5

Write-Host "Project Board update complete!"
