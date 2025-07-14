```markdown
---

## ⚙️ Prerequisites
Windows LMAO
````

---

## ▶️ Installation & Usage

1. **Clone** or **download** this repository:

   ```bash
   git clone https://github.com/Mody404/TITAN_PRIVATE-Cleanup.git
   cd TITAN_PRIVATE-Cleanup
   ```

2. **Open PowerShell as Administrator**.

3. **Allow scripts** in this session:

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   ```

4. **Launch** the cleanup script:

   ```powershell
   .\UltimateCleanup.ps1
   ```

5. **Follow** the interactive prompts to:

   * Review and delete any unrecognized local users
   * Confirm removal of Scheduled Tasks or Run-entries
   * Observe progress and logging output

6. **Reboot** your machine to finalize removal of any locked files or profiles.

---

## 📖 Example Run

```powershell
PS C:\TITAN_PRIVATE-Cleanup> Set-ExecutionPolicy Bypass -Scope Process -Force
PS C:\TITAN_PRIVATE-Cleanup> .\UltimateCleanup.ps1

[INFO] Running as user: Administrator
[INFO] Starting cleanup log at C:\Users\Administrator\Desktop\cleanup_20250714_174221.log

=== Local Users ===
Name            Enabled
----            -------
Administrator   True
Guest           False
server          True
backupUser      True

Enter any usernames to delete (comma-separated), or press Enter to skip: backupUser
[INFO] Manually deleted user backupUser

Delete local user 'server'? (Y/N): Y
[INFO] Deleted user server

...

[INFO] Blocking d3co4r.duckdns.org and 79.124.62.122
[INFO] Deleted profile folder C:\Users\server
[INFO] Removed IFEO key ...\procexp.exe
[INFO] Cleanup complete! Log saved to C:\Users\Administrator\Desktop\cleanup_20250714_174221.log
Please reboot to finalize.
```

---

## ❓ FAQ

* **Why do I need to reboot?**
  Certain profiles or files locked during cleanup are scheduled for deletion on next boot via `PendingFileRenameOperations`.

* **Will it delete my personal data?**
  It only targets specific user profiles (`server`, `moda`, `moba`), known malware paths, and registry keys tied to the malware. Always review prompts before confirming.

* **Can I use this in a domain environment?**
  This script manages **local** users and settings only. For Active Directory user removal, use `Remove-ADUser` or your domain management tools.

---

## 📝 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

© 2025 **Mody404** · [GitHub](https://github.com/Mody404)

```
```
