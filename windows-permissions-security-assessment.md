# Inlanefreight HR Share Security Assessment & Remediation

**Category:** Windows Security / Access Control
**Tools used:** PowerShell, Command Prompt, Windows Computer Management, `icacls`, `reg`
**Skills demonstrated:** NTFS vs. share permissions, Active Directory/local group-based access control, least-privilege design, command-line service auditing

---

## 1. Scenario

Inlanefreight experienced a security incident in which a disgruntled employee in the Marketing department accessed an internally hosted HR file share and deleted several confidential files and folders. The data was restored from backup, but the incident raised a more serious concern: **why was a Marketing employee able to reach the HR share at all?**

A follow-up security assessment found that the IT team did not have a clear understanding of how Windows NTFS and share permissions interact. This write-up documents a hands-on remediation exercise I ran to demonstrate correct, least-privilege file-sharing configuration, and to show how to audit services from the command line for signs of tampering — directly addressing both the access-control gap and the detection gap exposed by the incident.

**Objective:** Build a properly access-controlled HR share from scratch, using a dedicated security group rather than broad default permissions, and verify — empirically, not just by configuration — that only the intended group can reach the data.

---

## 2. Environment

- Standalone Windows 10 Enterprise workstation (workgroup, not domain-joined)
- Administrative PowerShell and Command Prompt access
- Local user/group management (no Active Directory available in this environment — see Section 6 for why that distinction matters)

---

## 3. Task Breakdown

The exercise mirrored a realistic remediation checklist:

1. Create a shared folder, `Company Data`
2. Create a subfolder, `HR`, inside it
3. Create a local user, `Jim`, representing an HR staff member
4. Create a local security group, `HR`
5. Add `Jim` to the `HR` group
6. Configure share **and** NTFS permissions on `Company Data`, restricted to the `HR` group only
7. Configure separate, explicit NTFS permissions on the `HR` subfolder
8. Demonstrate command-line service auditing, as part of the broader "check for tampering" training goal

---

## 4. Implementation

### 4.1 Creating the user and group (PowerShell)

Rather than using the GUI, I created the local user and group entirely via PowerShell, which is both faster and more auditable (the commands themselves form a record of exactly what was done):

```powershell
# Create the user
$password = Read-Host -AsSecureString "Enter password for Jim"
New-LocalUser -Name "Jim" -Password $password -PasswordNeverExpires:$false

# Create the group and add Jim to it
New-LocalGroup -Name "HR"
Add-LocalGroupMember -Group "HR" -Member "Jim"

# Verify
Get-LocalUser -Name "Jim"
Get-LocalGroupMember -Group "HR"
```

A deliberate configuration choice here: `New-LocalUser` does **not** force a password change at next logon by default, satisfying the requirement to leave "User must change password at logon" unchecked, without any extra flag.

### 4.2 Creating and sharing the folder structure

```powershell
mkdir "C:\Company Data"
mkdir "C:\Company Data\HR"

New-SmbShare -Name "Company Data" -Path "C:\Company Data" -FullAccess "Administrators"
```

### 4.3 Locking down Share Permissions

By default, `New-SmbShare` grants the `Everyone` group access — the exact pattern that almost certainly enabled the original incident. The first real remediation step is removing that default entry and replacing it with the specific group that should have access:

```powershell
Revoke-SmbShareAccess -Name "Company Data" -AccountName "Everyone" -Force
Grant-SmbShareAccess -Name "Company Data" -AccountName "HR" -AccessRight Change -Force
```

`Change` access at the share level includes `Read`, satisfying the "Allow Change & Read" requirement without needing two separate grants.

### 4.4 Locking down NTFS Permissions

Share permissions and NTFS permissions are evaluated independently, and the **more restrictive of the two always wins**. Fixing the share permission alone is not sufficient — the underlying NTFS ACL on the folder also defaults to broad access (typically the built-in `Users` or `Authenticated Users` group) and must be addressed separately:

```powershell
icacls "C:\Company Data" /inheritance:d
icacls "C:\Company Data" /remove:g "Users"
icacls "C:\Company Data" /grant "HR:(M,RX,R,W)"
```

- `/inheritance:d` disables inheritance from the parent folder and converts existing inherited entries into explicit ones, so they can be cleanly removed instead of silently reappearing.
- `/remove:g` strips the default group.
- `/grant "HR:(M,RX,R,W)"` grants the HR group Modify, Read & Execute, Read, and Write — covering every permission specified in the task ("List Folder Contents" is implied by Read & Execute on a directory).

The same three operations were repeated on the `HR` subfolder independently, rather than relying on inheritance from the parent:

```powershell
icacls "C:\Company Data\HR" /inheritance:d
icacls "C:\Company Data\HR" /remove:g "Users"
icacls "C:\Company Data\HR" /grant "HR:(M,RX,R,W)"
```

Treating the subfolder's permissions as a separate, explicit configuration — rather than trusting inheritance — means a future change to the parent folder's ACL can't accidentally loosen access to the more sensitive HR subfolder.

### 4.5 Verification

```powershell
icacls "C:\Company Data"
icacls "C:\Company Data\HR"
Get-SmbShareAccess -Name "Company Data"
```

Confirmed: only the `HR` group (plus built-in Administrators/System, which retain management access by design) appeared on each ACL, and the share-level permission list no longer contained `Everyone`.

---

## 5. Empirical Testing (not just configuration review)

Configuring permissions correctly is only half the job — the other half is *proving* they work as intended, rather than assuming they do. I tested from two angles:

**5.1 Negative test — my own account (not an HR group member)**

Attempting to open `Company Data` via File Explorer under my own (non-HR) account correctly produced:

> *"You don't currently have permission to access this folder."*

Windows also offered a "Continue" option to self-grant access — I initially clicked it during testing, which added my own account back onto the NTFS ACL with Full Control. Catching and reversing this was itself a useful finding: **administrator accounts can always override NTFS denial via ownership-taking, even when correctly excluded from the ACL.** This is an important caveat to document for the IT team — the fix, `icacls ... /remove`, is simple, but the underlying behavior (admins can self-grant) is a standing exception to "least privilege" that any access-control review needs to account for.

```powershell
icacls "C:\Company Data" /remove "ADEBAMIDELE-OJO\user"
```

**5.2 Positive test — Jim, as an HR group member**

Since the login/switch-user screen did not reliably list the local test account, I used `runas` to spawn a shell running explicitly as Jim, which is a more direct and scriptable test than relying on interactive login anyway:

```powershell
runas /user:Jim cmd.exe
```

From that shell, running as `ADEBAMIDELE-OJO\Jim`:

```cmd
cd "C:\Company Data"
dir
cd HR
dir
```

Both the parent folder and the HR subfolder listed successfully — confirming that a genuine HR group member has full, correct access, while a non-member (including an administrator, absent an explicit override) does not.

This before/after result — my own account blocked, Jim's account (HR member) allowed — is the direct, demonstrable fix for the root cause of the original incident: a Marketing employee, not a member of the HR group, would be blocked by this configuration at both the share and NTFS layers.

---

## 6. Command-Line Service Auditing

The second half of the training objective was showing how to check services from the command line for signs of tampering, since the original incident also raised concerns about visibility into system state beyond just file access.

```powershell
# Quick status
Get-Service -Name <ServiceName> | Format-List *

# Full detail, including the account running it and its executable path
Get-CimInstance Win32_Service -Filter "Name='<ServiceName>'" |
    Select Name, DisplayName, State, StartMode, StartName, PathName
```

`Get-Service` alone only reports status (`Running`/`Stopped`) and display name. The CIM/WMI-based query is the more useful one for a security review, because it surfaces:

- **`StartName`** — the account context the service runs under. A service that should run as `LocalSystem` but is instead configured under a user account is a red flag.
- **`PathName`** — the actual executable path (and any arguments). A legitimate-sounding service name pointing to an executable in a temp directory, user profile, or otherwise unexpected location is a classic persistence/tampering indicator.

This ties back to the assessment's broader point: the IT team needed not just correct permissions, but the habit of checking *what's actually running and from where*, rather than trusting a service name at face value.

---

## 7. Design Notes and Caveats

- **Local groups vs. Active Directory:** This exercise used local users/groups rather than AD, since the available environment was a standalone workgroup machine rather than a domain. In a real enterprise environment like Inlanefreight's, this would be implemented with a Domain Security Group and `Get-ADUser`/`Get-ADGroup` rather than `Get-LocalUser`/`Get-LocalGroup` — the permissions logic (share + NTFS, least privilege, explicit inheritance) is identical either way, but centralized AD groups scale across many machines and shares in a way local groups don't.
- **Share vs. NTFS permissions are evaluated independently.** This was the central misunderstanding the assessment identified in the IT team, and it's worth stating plainly: the *effective* permission a user ends up with is always the more restrictive of the two. Fixing one without the other leaves a gap (or an unintended restriction).
- **Disabling inheritance is a deliberate, explicit act** — it should be done at each level where permissions genuinely need to differ (here, both `Company Data` and its `HR` subfolder), rather than relying on a single top-level configuration to cascade correctly forever.
- **Administrators can self-override NTFS denial.** This isn't a misconfiguration — it's inherent to how Windows ownership and privilege elevation work — but it means "the ACL doesn't list this account" is not an absolute guarantee for an administrative account. Any access review should note which accounts have local admin rights on the machine hosting the share, since those accounts always have a path around NTFS ACLs if needed.

---

## 8. Outcome

By the end of the exercise, `Company Data` and its `HR` subfolder were configured so that only members of the `HR` local security group had access, at both the share and NTFS permission layers, with inheritance explicitly broken and default broad-access groups removed. Access was verified empirically from both a non-member account (blocked) and a group-member account (allowed), rather than relying on the permissions dialog alone. This directly demonstrates the fix for the root cause of the original incident — a non-HR employee should never have been able to reach the HR share in the first place — and gives the Inlanefreight IT team a concrete, tested template for correctly scoping any similarly sensitive share going forward.
