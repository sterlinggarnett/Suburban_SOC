$repo = "sterlinggarnett/cis3353_s26_TL_SG_MF"
$milestone6 = "Milestone 6: Presentation"

Write-Host "Creating Task 1 issue (PL - sterlinggarnett)..."
$t1 = gh issue create --repo $repo `
  --title "[Task] Rename repository to cis3353_s26_TL_SG_MF" `
  --body "**Owner:** PL - Sterling Garnett (@sterlinggarnett)`n**Priority:** CRITICAL | **Time:** 20 min`n`n## Description`nRename (or fork) the repo to follow the naming convention: cis3353_s26_TL_SG_MF. Go to GitHub Settings > Repository name.`n`n## Acceptance Criteria`n- [x] Repository renamed to ``cis3353_s26_TL_SG_MF```n- [x] All local clones updated: ``git remote set-url origin <new_url>```n`n## Status`n**COMPLETED** - Renamed on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "sterlinggarnett" `
  --label "user-story"
Write-Host $t1

Write-Host "Creating Task 3 issue (SA - voltron-1)..."
$t3 = gh issue create --repo $repo `
  --title "[Task] Add Team Members table to README.md" `
  --body "**Owner:** SA - Tommy Lammers (@voltron-1)`n**Priority:** CRITICAL | **Time:** 15 min`n`n## Description`nAdd the Team Members table to README.md using Appendix C format: Name | GitHub Username | Role - one row for each of the three members.`n`n## Acceptance Criteria`n- [x] Table added with Name, GitHub Username, Role columns`n- [x] Tommy Lammers | @voltron-1 | Security Analyst / Manager`n- [x] Sterling Garnett | @sterlinggarnett | System Architect / Engineer / Project Lead`n- [x] Maria Frausto | @megifrausto-design | Design / Docs Lead / Manager`n`n## Status`n**COMPLETED** - Committed to ``merge-to-main`` on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host $t3

Write-Host "Creating Task 4 issue (SA - voltron-1)..."
$t4 = gh issue create --repo $repo `
  --title "[Task] Add Course Modules section to README.md" `
  --body "**Owner:** SA - Tommy Lammers (@voltron-1)`n**Priority:** CRITICAL | **Time:** 20 min`n`n## Description`nAdd the Course Modules section to README.md. List which 3+ modules from the course the project covers (Mod 2, 8, 9 are strong fits) and write 1-2 sentences connecting each module to the pipeline.`n`n## Acceptance Criteria`n- [x] Module 2 (Network Fundamentals & Traffic Analysis) linked to pipeline`n- [x] Module 8 (Intrusion Detection Systems) linked to Zeek`n- [x] Module 9 (Security Operations & Incident Response) linked to ELK stack`n`n## Status`n**COMPLETED** - Committed to ``merge-to-main`` on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host $t4

Write-Host "Creating Task 5 issue (SA - voltron-1)..."
$t5 = gh issue create --repo $repo `
  --title "[Task] Add Project Status milestone table to README.md" `
  --body "**Owner:** SA - Tommy Lammers (@voltron-1)`n**Priority:** CRITICAL | **Time:** 10 min`n`n## Description`nAdd the Project Status milestone table to README.md. List M1 through M4 with their current status (Complete / In Progress / Not Started).`n`n## Acceptance Criteria`n- [x] M1: Topology - Complete`n- [x] M2: Data Acquisition - Complete`n- [x] M3: Processing Pipeline - Complete`n- [x] M4: Data Visualization - Complete`n- [x] M5-M8: In Progress`n`n## Status`n**COMPLETED** - Committed to ``merge-to-main`` on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host $t5

Write-Host "Creating Task 6 issue (SEC - megifrausto-design)..."
$t6 = gh issue create --repo $repo `
  --title "[Task] Create MIT LICENSE file in repository root" `
  --body "**Owner:** SEC - Maria Frausto (@megifrausto-design)`n**Priority:** CRITICAL | **Time:** 10 min`n`n## Description`nCreate a LICENSE file in the repo root. Select MIT license and commit.`n`n## Acceptance Criteria`n- [x] LICENSE file exists in repository root`n- [x] MIT License with correct copyright holders`n- [x] README License section references the file`n`n## Status`n**COMPLETED** - Committed to ``merge-to-main`` on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "megifrausto-design" `
  --label "user-story"
Write-Host $t6

Write-Host "Creating Task 7 issue (ALL)..."
$t7 = gh issue create --repo $repo `
  --title "[Task] Document Delegated Commits approach in Wiki and README" `
  --body "**Owner:** ALL - Tommy Lammers, Sterling Garnett, Maria Frausto`n**Priority:** CRITICAL | **Time:** 15 min`n`n## Description`nTeam vote: decide Individual Commits or Delegated Commits (Part 2 Section 6). Document the decision in a new Wiki page titled 'Commit-Approach' and add a note to the README.`n`n## Acceptance Criteria`n- [x] Team voted on Delegated Commits approach`n- [x] Wiki page 'Commit-Approach' created at https://github.com/sterlinggarnett/cis3353_s26_TL_SG_MF/wiki/Commit-Approach`n- [x] README Contribution Guidelines updated with commit approach note`n`n## Status`n**COMPLETED** - Wiki page pushed and README updated on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "sterlinggarnett" `
  --assignee "voltron-1" `
  --assignee "megifrausto-design" `
  --label "user-story"
Write-Host $t7

Write-Host "Creating Task 8 issue (PL - sterlinggarnett)..."
$t8 = gh issue create --repo $repo `
  --title "[Task] Enable GitHub Wiki and create Home page" `
  --body "**Owner:** PL - Sterling Garnett (@sterlinggarnett)`n**Priority:** HIGH | **Time:** 20 min`n`n## Description`nVerify the GitHub Wiki is enabled (Settings > Features > Wikis). Create or update the Wiki Home page as a table of contents linking to: Sprint Notes, Architecture, Final Report.`n`n## Acceptance Criteria`n- [x] Wiki enabled on repository`n- [x] Home page created with table of contents`n- [x] Commit-Approach page created`n- [x] Links to Sprint Notes, Architecture, Final Report, Commit-Approach`n`n## Status`n**COMPLETED** - Wiki enabled and pages created on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "sterlinggarnett" `
  --label "user-story"
Write-Host $t8

Write-Host "Creating Task 9 issue (PL - sterlinggarnett)..."
$t9 = gh issue create --repo $repo `
  --title "[Task] Verify GitHub Milestones M1-M4 exist with due dates" `
  --body "**Owner:** PL - Sterling Garnett (@sterlinggarnett)`n**Priority:** HIGH | **Time:** 15 min`n`n## Description`nVerify the GitHub Milestones exist (Issues > Milestones). Create M1-M4 if missing. Add a due date (Friday May 1) and a one-line description per milestone.`n`n## Acceptance Criteria`n- [x] Milestone 1: Topology - due May 1`n- [x] Milestone 2: Data Acquisition - due May 1`n- [x] Milestone 3: Processing Pipeline - due May 1`n- [x] Milestone 4: Data Visualization - due May 1`n`n## Status`n**COMPLETED** - All M1-M4 milestones verified with May 1 due dates on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "sterlinggarnett" `
  --label "user-story"
Write-Host $t9

Write-Host "Creating Task 10 issue (PL - sterlinggarnett)..."
$t10 = gh issue create --repo $repo `
  --title "[Task] Verify GitHub Project Board columns and sprint iterations" `
  --body "**Owner:** PL - Sterling Garnett (@sterlinggarnett)`n**Priority:** HIGH | **Time:** 20 min`n`n## Description`nVerify the GitHub Project Board exists with Backlog / Ready / In Progress / In Review / Done columns. Configure sprint iterations matching the class schedule. Add any open issues to the board.`n`n## Acceptance Criteria`n- [x] Project Board has Backlog, Ready, In Progress, In Review, Done columns`n- [x] Sprint iterations configured (Iteration 1 through 5)`n- [x] All 11 open User Story issues added to the board`n- [x] Issues assigned to Iteration 1 with Backlog status`n`n## Status`n**COMPLETED** - Project Board verified and all issues mapped on 2026-04-29" `
  --milestone $milestone6 `
  --assignee "sterlinggarnett" `
  --label "user-story"
Write-Host $t10

Write-Host "All task issues created!"
