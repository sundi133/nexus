# HR-driven joiners, movers and leavers

Connect **BambooHR** or **Workday** under **Directory sync → Connect a directory**, and HR becomes the source of truth for who works here. It uses the same machinery as the other directories: test before saving, a preview before anything changes, scheduled syncs (every 15 minutes to a day), the mass-change guard, and sealed credentials.

| | Joiners | Movers | Leavers |
|---|---|---|---|
| What HR says | Active, with a work email | New title, department or supervisor | Terminated, or their termination date (their last day) has passed |
| What Nexus does | Creates the person (staged, or invited by email) | Updates title and department, sets their **manager**, and moves them between department groups | **Offboards** them (or suspends them, or nothing: your choice) |

- **Leavers.** Someone leaves the day after their last day (UTC), or as soon as HR marks them inactive. With **Offboard**, that's the full offboarding: sessions, admin roles, groups, app accounts (deprovisioned through SCIM), devices unassigned, and their laptop accounts disabled. It's recorded as `user.offboarded` with HR's reason, for example "Left the company in BambooHR (last day 2026-09-30)". Offboarding is for good. **Suspend** is reversible and reactivates people HR marks active again.
- **Mass-change guard.** If more than 10% of people (at least 5) would leave in one sync, it waits for an admin to approve. A report filter gone wrong can't offboard the company.
- **Managers.** Taken from the HR supervisor when both people are synced. They drive access-request approvals and dynamic groups. A change that would make a loop (A manages B manages A) is refused and listed as skipped.
- **Departments as groups** (optional). One group per department, whose members follow HR. Use them to assign apps, policies and app deployments.
- **Preview.** The preview lists new people, updates, new managers, and who would be offboarded or suspended, with the reason.

## BambooHR

1. As a BambooHR user who can see all employees, open your name → **API Keys** → **Add New Key**.
2. In Nexus, enter your company subdomain (`acme` for acme.bamboohr.com) and the key.

Nexus runs one custom report through the API with id, name, preferred name, work email, job title, department, supervisor, status and termination date. It only reads.

## Workday

1. Create an **integration system user** (ISU) with view access to workers.
2. Create an Advanced **custom report** of workers with these columns: employee ID, work email, first and last name, business title, department (or supervisory organization), manager's employee ID, active status, and termination date. **Enable it as a web service** and share it with the ISU.
3. Copy the report's JSON URL (**Actions → Web Service → View URLs**). It contains `/ccx/service/customreport2/`.
4. In Nexus, enter the URL, the ISU and its password. If your columns are named differently from the defaults (`Employee_ID`, `Email_Address`, `First_Name`, `Last_Name`, `Business_Title`, `Department`, `Manager_Employee_ID`, `Active`, `Termination_Date`), rename them under **Report columns**. Workday's reference-style values (lists, `Descriptor` objects) are read as text.

The URL must be https on a Workday host (`…workday.com` or `…myworkday.com`), and it's checked against private addresses.

## Limits

- **Start dates.** A new hire is created as soon as HR lists them as active with a work email. There's no start-date hold yet. Keep them staged by turning off invitations if you create people ahead of their first day.
- **New credentials.** To use a new BambooHR key or Workday password, connect again and remove the old connection. People are matched again by email, so nothing is duplicated.
- **Time zone.** Termination dates are compared in UTC.
