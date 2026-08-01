!macro VARMLEN_STOP_SERVICE
  nsExec::ExecToLog 'powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$$service = Get-Service -Name VarmlenService -ErrorAction SilentlyContinue; if ($$service) { Stop-Service -Name VarmlenService -Force -ErrorAction SilentlyContinue; $$service.WaitForStatus(''Stopped'', ''00:00:15'') }"'
!macroend

!macro VARMLEN_BACKUP_FILE NAME
  IfFileExists "$INSTDIR\${NAME}" 0 +2
    CopyFiles /SILENT "$INSTDIR\${NAME}" "$PLUGINSDIR\varmlen-service-backup\${NAME}"
!macroend

!macro VARMLEN_RESTORE_FILE NAME
  IfFileExists "$PLUGINSDIR\varmlen-service-backup\${NAME}" 0 +2
    CopyFiles /SILENT "$PLUGINSDIR\varmlen-service-backup\${NAME}" "$INSTDIR\${NAME}"
!macroend

!macro VARMLEN_ROLLBACK_SERVICE
  !insertmacro VARMLEN_STOP_SERVICE
  ${If} $R8 == "1"
    !insertmacro VARMLEN_RESTORE_FILE "varmlen-service.exe"
    !insertmacro VARMLEN_RESTORE_FILE "xray.exe"
    !insertmacro VARMLEN_RESTORE_FILE "wintun.dll"
    !insertmacro VARMLEN_RESTORE_FILE "geoip.dat"
    !insertmacro VARMLEN_RESTORE_FILE "geosite.dat"
    nsExec::ExecToLog 'sc.exe config VarmlenService binPath= "\"$INSTDIR\varmlen-service.exe\"" start= auto obj= LocalSystem'
    nsExec::ExecToLog 'sc.exe start VarmlenService'
  ${Else}
    nsExec::ExecToLog '"$INSTDIR\varmlen-service.exe" --cleanup'
    nsExec::ExecToLog 'sc.exe delete VarmlenService'
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  SetDetailsPrint both
  StrCpy $R8 "0"
  nsExec::ExecToStack 'sc.exe query VarmlenService'
  Pop $0
  Pop $1
  ${If} $0 == 0
    StrCpy $R8 "1"
    !insertmacro VARMLEN_STOP_SERVICE
    CreateDirectory "$PLUGINSDIR\varmlen-service-backup"
    !insertmacro VARMLEN_BACKUP_FILE "varmlen-service.exe"
    !insertmacro VARMLEN_BACKUP_FILE "xray.exe"
    !insertmacro VARMLEN_BACKUP_FILE "wintun.dll"
    !insertmacro VARMLEN_BACKUP_FILE "geoip.dat"
    !insertmacro VARMLEN_BACKUP_FILE "geosite.dat"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  CreateDirectory "$COMMONAPPDATA\Varmlen"

  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$$interactive = (Get-CimInstance Win32_ComputerSystem).UserName; if ([string]::IsNullOrWhiteSpace($$interactive)) { throw ''No interactive user is signed in'' }; $$account = New-Object System.Security.Principal.NTAccount($$interactive); $$sid = $$account.Translate([System.Security.Principal.SecurityIdentifier]); [System.IO.File]::WriteAllText(''$COMMONAPPDATA\Varmlen\installed-user.sid'', $$sid.Value); $$acl = New-Object System.Security.AccessControl.DirectorySecurity; $$admins = New-Object System.Security.Principal.SecurityIdentifier(''S-1-5-32-544''); $$system = New-Object System.Security.Principal.SecurityIdentifier(''S-1-5-18''); $$acl.SetOwner($$admins); $$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit; $$propagation = [System.Security.AccessControl.PropagationFlags]::None; $$allow = [System.Security.AccessControl.AccessControlType]::Allow; $$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($$system, ''FullControl'', $$inherit, $$propagation, $$allow))); $$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($$admins, ''FullControl'', $$inherit, $$propagation, $$allow))); [System.IO.Directory]::SetAccessControl(''$COMMONAPPDATA\Varmlen'', $$acl)"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    !insertmacro VARMLEN_ROLLBACK_SERVICE
    MessageBox MB_ICONSTOP "Varmlen could not initialize its protected service state directory.$\r$\n$1"
    Abort
  ${EndIf}

  ${If} $R8 == "1"
    nsExec::ExecToStack 'sc.exe config VarmlenService binPath= "\"$INSTDIR\varmlen-service.exe\"" start= auto obj= LocalSystem DisplayName= "Varmlen VPN Service"'
  ${Else}
    nsExec::ExecToStack 'sc.exe create VarmlenService binPath= "\"$INSTDIR\varmlen-service.exe\"" start= auto obj= LocalSystem DisplayName= "Varmlen VPN Service"'
  ${EndIf}
  Pop $0
  Pop $2
  ${If} $0 != 0
    !insertmacro VARMLEN_ROLLBACK_SERVICE
    MessageBox MB_ICONSTOP "Varmlen could not configure its Windows service.$\r$\n$2"
    Abort
  ${EndIf}

  nsExec::ExecToLog 'sc.exe description VarmlenService "Native TUN, DNS and WFP enforcement for Varmlen"'
  nsExec::ExecToLog 'sc.exe failure VarmlenService reset= 86400 actions= restart/2000/restart/5000/restart/10000'
  nsExec::ExecToStack 'sc.exe start VarmlenService'
  Pop $0
  Pop $2
  ${If} $0 != 0
    !insertmacro VARMLEN_ROLLBACK_SERVICE
    MessageBox MB_ICONSTOP "VarmlenService could not start; the previous service was restored.$\r$\n$2"
    Abort
  ${EndIf}

  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -Command "for ($$attempt = 0; $$attempt -lt 20; $$attempt++) { & ''$INSTDIR\varmlen-service.exe'' --health; if ($$LASTEXITCODE -eq 0) { exit 0 }; Start-Sleep -Milliseconds 500 }; exit 1"'
  Pop $0
  Pop $2
  ${If} $0 != 0
    !insertmacro VARMLEN_ROLLBACK_SERVICE
    MessageBox MB_ICONSTOP "VarmlenService did not become IPC-ready; the previous service was restored.$\r$\n$2"
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro VARMLEN_STOP_SERVICE
  nsExec::ExecToStack '"$INSTDIR\varmlen-service.exe" --cleanup'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Varmlen could not remove its persistent WFP policy. Uninstall was stopped so the recovery executable remains available.$\r$\n$1"
    Abort
  ${EndIf}
  nsExec::ExecToStack 'sc.exe delete VarmlenService'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Varmlen could not remove its Windows service.$\r$\n$1"
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  RMDir /r "$COMMONAPPDATA\Varmlen"
!macroend
