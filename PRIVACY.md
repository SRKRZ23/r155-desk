# Privacy policy: R155 Desk

Last updated: 21 November 2026

R155 Desk is an Atlassian Forge app. It runs entirely on Atlassian's Forge platform. It has no backend of its
own, makes no calls to services outside Atlassian, and its developer has no access to your data.

## What the app reads
- Jira issues in the projects where it is used (summary, description, status, project, creation date), to detect
  software components and assess them.
- Confluence spaces and pages, only when an admin configures a space for audit records and a user publishes one.
- Your Atlassian account id, to record who saved an assessment.

## What the app stores, and where
- **On the Jira issue** (issue properties, stored by Atlassian): the assessment you save, including your account id
  and the time, and a short history of earlier assessments of that issue; a marker that the first-look note was posted.
- **In Forge storage** (hosted by Atlassian, per installation): the vehicle and ECU inventory an admin imports, and the
  app settings. The inventory describes products, not people.
- **In Confluence** (only if you publish): the audit record page, including the account id of the assessor.
- **In Teamwork Graph** (only if an admin connects the connector): one document per ECU and per vehicle line from the
  inventory. Atlassian removes this data when the connector is disconnected.
- **Jira comments**: the internal first-look note on new tickets (can be turned off on the admin page).

The app does not copy personal data to any system outside Atlassian and does not use it for any other purpose.

## AI
The Rovo agent and Rovo actions run inside Atlassian Rovo under your organisation's Rovo terms. The app itself does
not call any external AI service.

## Removing data
Uninstalling the app stops all processing. Issue properties, comments and Confluence pages remain in your site
like any other content and can be deleted by your admins. Forge storage for the installation is removed by Atlassian
according to the Forge platform rules.

## Contact
Questions: https://github.com/SRKRZ23/r155-desk/issues
