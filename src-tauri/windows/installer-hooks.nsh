!macro VARMLEN_STOP_SERVICE
  nsExec::ExecToLog 'powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$$service = Get-Service -Name VarmlenService -ErrorAction SilentlyContinue; if ($$service) { Stop-Service -Name VarmlenService -Force -ErrorAction SilentlyContinue; $$service.WaitForStatus(''Stopped'', ''00:00:15'') }"'
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro VARMLEN_STOP_SERVICE
  nsExec::ExecToLog 'sc.exe delete VarmlenService'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  CreateDirectory "$COMMONAPPDATA\Varmlen"

  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$$interactive = (Get-CimInstance Win32_ComputerSystem).UserName; if ([string]::IsNullOrWhiteSpace($$interactive)) { $$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { $$account = New-Object System.Security.Principal.NTAccount($$interactive); $$sid = $$account.Translate([System.Security.Principal.SecurityIdentifier]).Value }; [System.IO.File]::WriteAllText(''$COMMONAPPDATA\Varmlen\installed-user.sid'', $$sid); & icacls.exe ''$COMMONAPPDATA\Varmlen'' /inheritance:r /grant:r ''*S-1-5-18:(OI)(CI)F'' ''*S-1-5-32-544:(OI)(CI)F'' (''*'' + $$sid + '':(OI)(CI)M''); if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Varmlen could not initialize and secure its service state directory."
    Abort
  ${EndIf}

  nsExec::ExecToStack 'sc.exe create VarmlenService binPath= "\"$INSTDIR\varmlen-service.exe\"" start= auto obj= LocalSystem DisplayName= "Varmlen VPN Service"'
  Pop $0
  Pop $2
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Varmlen could not install its Windows service."
    Abort
  ${EndIf}

  nsExec::ExecToLog 'sc.exe description VarmlenService "Native TUN, DNS and WFP enforcement for Varmlen"'
  nsExec::ExecToLog 'sc.exe failure VarmlenService reset= 86400 actions= restart/2000/restart/5000/restart/10000'
  nsExec::ExecToStack 'sc.exe start VarmlenService'
  Pop $0
  Pop $2
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "VarmlenService could not start. The installation was left fail-closed."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro VARMLEN_STOP_SERVICE
  nsExec::ExecToLog '"$INSTDIR\varmlen-service.exe" --cleanup'
  nsExec::ExecToLog 'sc.exe delete VarmlenService'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  RMDir /r "$COMMONAPPDATA\Varmlen"
!macroend
