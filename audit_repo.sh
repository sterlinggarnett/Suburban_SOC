#!/bin/bash

# ==============================================================================
# UIW_SOC - Repository Posture & Agile Gap Analysis
# ==============================================================================

REPO="voltron-1/UIW_SOC"

# ANSI Color Codes for terminal formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}  Executing Gap Analysis for: $REPO ${NC}"
echo -e "${BLUE}======================================================${NC}\n"

# ------------------------------------------------------------------------------
# 1. REPOSITORY POSTURE & DOCUMENTATION
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Phase 1: Repository Posture & Documentation Audit${NC}"

# Check for README
if gh api repos/$REPO/contents/README.md >/dev/null 2>&1; then
    echo -e "${GREEN}  [PASS] README.md found.${NC}"
else
    echo -e "${RED}  [FAIL] Missing README.md - Critical for project onboarding.${NC}"
fi

# Check for .gitignore
if gh api repos/$REPO/contents/.gitignore >/dev/null 2>&1; then
    echo -e "${GREEN}  [PASS] .gitignore found.${NC}"
else
    echo -e "${RED}  [FAIL] Missing .gitignore - High risk of committing sensitive files (like .env).${NC}"
fi

# Check for LICENSE
if gh api repos/$REPO/contents/LICENSE >/dev/null 2>&1; then
    echo -e "${GREEN}  [PASS] LICENSE found.${NC}"
else
    echo -e "${RED}  [FAIL] Missing LICENSE - Legal bounds for the UIW project are undefined.${NC}"
fi

echo ""

# ------------------------------------------------------------------------------
# 2. AGILE BOARD & PROJECT MANAGEMENT GAPS
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Phase 2: Agile Board Integrity Audit${NC}"

# Calculate Total Open Issues
TOTAL_ISSUES=$(gh issue list --repo $REPO --state open --json id --jq 'length')
echo "  Total Open Tasks: $TOTAL_ISSUES"

# Find Unassigned Tasks
UNASSIGNED=$(gh issue list --repo $REPO  "@none" --state open --json id --jq 'length')
if [ "$UNASSIGNED" -eq 0 ]; then
    echo -e "${GREEN}  [PASS] All tasks are assigned to a team member.${NC}"
else
    echo -e "${RED}  [GAP]  $UNASSIGNED tasks have no assignee. (Who is doing the work?)${NC}"
fi

# Find Tasks without Milestones
NO_MILESTONE=$(gh issue list --repo $REPO --search "no:milestone" --state open --json id --jq 'length')
if [ "$NO_MILESTONE" -eq 0 ]; then
    echo -e "${GREEN}  [PASS] All tasks are mapped to a timeline.${NC}"
else
    echo -e "${RED}  [GAP]  $NO_MILESTONE tasks are missing a Milestone target date.${NC}"
fi

# Find Tasks without Labels (Epics)
NO_LABEL=$(gh issue list --repo $REPO --search "no:label" --state open --json id --jq 'length')
if [ "$NO_LABEL" -eq 0 ]; then
    echo -e "${GREEN}  [PASS] All tasks are categorized by an Epic/Label.${NC}"
else
    echo -e "${RED}  [GAP]  $NO_LABEL tasks are uncategorized (Orphaned tasks).${NC}"
fi

echo ""

# ------------------------------------------------------------------------------
# 3. SUMMARY & NEXT STEPS
# ------------------------------------------------------------------------------
echo -e "${BLUE}======================================================${NC}"
echo -e "Audit Complete. Review the ${RED}[FAIL]${NC} and ${RED}[GAP]${NC} metrics above."
echo -e "${BLUE}======================================================${NC}"
