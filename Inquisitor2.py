def _cscan(content):
    detection = ""
    Score = 0

    if not type(content) is bytes: raise TypeError('Content must be encoded before Scanning')

    if b'hatsploit' in content:
        detection += '🕴️' + ('Hatsploit')
        Score = Score + 3
    if b'net user' in content:
        detection += '🕴️' + ('UserSettings(Looks at or edits Users.)')
        Score = Score + 16
    if b'net1 user' in content:
        detection += '🕴️' + ('NetPassword')
        Score = Score + 16
    if b'net share' in content:
        detection += '🕴️' + ('NetShare')
        Score = Score + 7
    if b'net1 share' in content:
        detection += '🕴️' + ('NetShare')
        Score = Score + 7
    if b'%COMSPEC% /C start %COMSPEC% /C \\WINDOWS\\Temp' in content:
        Score = Score + 3
    if b'bash -c \'exec bash -i &>/dev/tcp/' in content:
        detection += '🕴️' + ('Bash')
        Score = Score + 3
    if b'zsh -c \'zmodload zsh/net/tcp && ztcp' in content:
        detection += '🕴️' + ('Zsh')
        Score = Score + 3
    if b'zsh >&$REPLY 2>&$REPLY 0>&$REPLY\'' in content:
        detection += '🕴️' + ('Zsh')
        Score = Score + 3
    if b'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc' in content:
        detection += '🕴️' + ('NCat')
        Score = Score + 3
    if b'TF=$(mktemp -u); mkfifo $TF && telnet' in content:
        detection += '🕴️' + ('telnet')
        Score = Score + 3
    if b'0<$TF | /bin sh 1>$TF' in content:
        Score = Score + 3
    if b'bash -c \'echo -e "POST / HTTP/0.9 $(<' in content:
        detection += '🕴️' + ('BashHttp')
        Score = Score + 3
    if b'> /dev/tcp/' in content:
        detection += '🕴️' + ('BashTCP')
        Score = Score + 3
    if b'D$UPPPj' in content:
        detection += '🕴️' + ('Mimikatz')
        Score = Score + 19
    if b'D$Ej' in content:
        detection += '🕴️' + ('Mimikatz')
        Score = Score + 19
    if b'|$JQu0' in content:
        detection += '🕴️' + ('Mimikatz')
        Score = Score + 19
    if b'D$CjNh' in content:
        detection += '🕴️' + ('Mimikatz')
        Score = Score + 19
    if b'|$BQun' in content:
        detection += '🕴️' + ('Mimikatz')
        Score = Score + 19
    if b'taskhcst' in content:
        detection += '🕴️' + ('wannacry')
        Score = Score + 19
    if b'lsasvs' in content:
        detection += '🕴️' + ('wannacry')
        Score = Score + 19
    if b'cscc' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
        Score = Score + 19
    if b'infpub' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
        Score = Score + 19
    if b'perfc' in content:
        detection += '🕴️' + ('Petya')
        Score = Score + 19
    if b'taskkill' in content:
        detection += '🕴️' + ('taskkill')
        Score = Score + 3
    if b'pskill' in content:
        detection += '🕴️' + ('taskkill')
        Score = Score + 3
    if b'pskill64' in content:
        detection += '🕴️' + ('taskkill')
        Score = Score + 3
    if b'tskill' in content:
        detection += '🕴️' + ('taskkill')
        Score = Score + 3
    if b'C:\\Windows' in content:
        detection += '🕴️' + ('SystemTamper')
        Score = Score + 3
    if b'C:\\Windows\\System32' in content:
        detection += '🕴️' + ('SystemTamper')
        Score = Score + 1
    if b'csrss' in content:
        detection += '🕴️' + ('SystemTamper')
        Score = Score + 4
    if b'wininit' in content:
        detection += '🕴️' + ('SystemTamper')
        Score = Score + 4
    if b'svchost' in content:
        detection += '🕴️' + ('ServiceTamper')
        Score = Score + 4
    if b'msmpeng' in content:
        detection += '🕴️' + ('ProtectionTamper')
        Score = Score + 4
    if b'ntoskrnl' in content:
        detection += '🕴️' + ('KernelTamper')
        Score = Score + 4
    if b'winlogon' in content:
        detection += '🕴️' + ('LoginTamper')
        Score = Score + 4
    if b'socket.socket(socket.AF_INET' in content:
        detection += '🕴️' + ('PYSocket')
        Score = Score + 3
    if b'wscript.exe /b /nologo /E:javascript' in content:
        detection += '🕴️' + ('vbsjs')
        Score = Score + 3
    if b'Invoke-Mimikatz' in content:
        detection += '🕴️' + ('Mimikatz')
        Score = Score + 21
    if b'copy \%%.*0' in content:
        detection += '🕴️' + ('Copyself')
        Score = Score + 3
    if b'cacls' in content:
        detection += '🕴️' + ('PermissionTamper')
        Score = Score + 4
    if b'takeown' in content:
        detection += '🕴️' + ('PermissionTamper')
        Score = Score + 4
    if b'RMDIR' in content:
        detection += '🕴️' + ('Deleter')
        Score = Score + 3
    if b'REPLACE' in content:
        detection += '🕴️' + ('Replace')
        Score = Score + 3
    if b'ASSOC' in content:
        detection += '🕴️' + ('assoc')
        Score = Score + 2
    if b'ATTRIB' in content:
        detection += '🕴️' + ('Attributes')
        Score = Score + 3
    if b'FSUTIL' in content:
        detection += '🕴️' + ('fsutil')
        Score = Score + 8
    if b'WMIC' in content:
        detection += '🕴️' + ('wmic')
        Score = Score + 5
    if b'wbadmin' in content:
        detection += '🕴️' + ('BackupTamper')
        Score = Score + 16
    if b'vssadmin' in content:
        detection += '🕴️' + ('ShadowcopyTamper')
        Score = Score + 16
    if b'wmic shadowcopy' in content:
        detection += '🕴️' + ('ShadowcopyTamper')
        Score = Score + 11
    if b'bcdedit' in content:
        detection += '🕴️' + ('BootEdit')
        Score = Score + 16
    if b'bcdedit /delete' in content:
        detection += '🕴️' + ('BootDel')
        Score = Score + 68
    if b'bcdedit/delete' in content:
        detection += '🕴️' + ('BootDel')
        Score = Score + 68
    if b'php -r \'$sock=fsockopen(getenv(' in content:
        detection += '🕴️' + ('PhpSock')
        Score = Score + 3
    if b'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'' in content:
        detection += '🕴️' + ('PSSocket')
        Score = Score + 3
    if b'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect' in content:
        detection += '🕴️' + ('PYSocket')
        Score = Score + 3
    if b'ruby -rsocket -e \\\'exit if fork;c=TCPSocket.new(ENV[' in content:
        detection += '🕴️' + ('RubyRSocket')
        Score = Score + 3
    if b'bash -c \'cat' in content:
        detection += '🕴️' + ('BashCat')
        Score = Score + 3
    if b'nc -l -p' in content:
        detection += '🕴️' + ('NCat')
        Score = Score + 1
    if b'nc -lnvp ;' in content:
        detection += '🕴️' + ('NCat')
        Score = Score + 1
    if b'python3 -m http.server' in content:
        detection += '🕴️' + ('PYHttp')
        Score = Score + 4
    if b'python -m SimpleHTTPServer' in content:
        detection += '🕴️' + ('PYHttp')
        Score = Score + 4
    if b'scp pl' in content:
        detection += '🕴️' + ('SCP')
        Score = Score + 4
    if b':~/destination -P' in content:
        Score = Score + 3
    if b'scp user@' in content:
        detection += '🕴️' + ('SCP')
        Score = Score + 4
    if b':~/path_to_file file_saved -P' in content:
        detection += '🕴️' + ('datpath')
        Score = Score + 5
    if b'document.cookie' in content:
        detection += '🕴️' + ('HTCookie')
        Score = Score + 3
    if b'getItem(\'access_token\')' in content:
        detection += '🕴️' + ('HTCookie')
        Score = Score + 3
    if b'UNION SELECT NULL,NULL,NULL' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'UNION ORDER BY 1' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'UNION SELECT @@version' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'UNION SELECT banner from v$version' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'UNION SELECT version' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'UNION SELECT table_name,NULL from INFORMATION_SCHEMA.TABLES' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'UNION SELECT table_name,NULL FROM all_tables' in content:
        detection += '🕴️' + ('SQL')
        Score = Score + 7
    if b'System.Windows.Forms' in content:
        detection += '🕴️' + ('WindowsForms')
        Score = Score + 7
    if b'PopUp' in content:
        detection += '🕴️' + ('Popup')
        Score = Score + 3
    if b'[\\w-]\{24}\\.[\\w-]\{6}\\.[\\w-]\{27}" /c:"mfa\\.[\\w-]\{84}' in content:
        detection += '🕴️' + ('Other')
        Score = Score + 21
    if b'hcrypt' in content:
        detection += '🕴️' + ('Hcrypt')
        Score = Score + 7
    if b'/Quarantine *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18' in content:
        Score = Score + 8
    if b'ConsentPromptBehaviorAdmin' in content:
        detection += '🕴️' + ('UACAdminConsentPromptTamper')
        Score = Score + 8
    if b'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\UX Configuration' in content:
        detection += '🕴️' + ('ProtectionTamper')
        Score = Score + 8
    if b'Notification_Suppress' in content:
        detection += '🕴️' + ('NotificationSuppresser')
        Score = Score + 8
    if b'DisableTaskMgr' in content:
        detection += '🕴️' + ('DisableTaskManager')
        Score = Score + 7
    if b'DisableCMD' in content:
        detection += '🕴️' + ('DisableCommandline')
        Score = Score + 7
    if b'DisableRegistryTools' in content:
        detection += '🕴️' + ('DisableRegistryTools')
        Score = Score + 7
    if b'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies' in content:
        detection += '🕴️' + ('PoliciesTamper')
        Score = Score + 8
    if b'NoRun' in content:
        detection += '🕴️' + ('NoRun')
        Score = Score + 1
    if b'windefend' in content:
        detection += '🕴️' + ('ProtectionTamper')
        Score = Score + 8
    if b'Add-MpPreference' in content:
        detection += '🕴️' + ('ProtectionTamper')
        Score = Score + 8
    if b'Start Menu\\Programs\\Startup' in content:
        detection += '🕴️' + ('Startup')
        Score = Score + 7
    if b'advfirewall' in content:
        detection += '🕴️' + ('Firewall')
        Score = Score + 7
    if b'//4mY2xzDQo=' in content:
        detection += '🕴️' + ('CanObfuscate')
        Score = Score + 4
    if b'certutil' in content:
        detection += '🕴️' + ('Certutil')
        Score = Score + 2
    if b'JKbtgdfd' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'510501002024' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_GentProcessID@0' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_ResumePhrocess@4' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_GetThureadList@12' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_SutspendProcess@4' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_GetPrkrocessList@8' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_GetPronhcessName@8' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_GetThrehjadContext@8' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_ReadRehmoteMemory@16' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_WriteRehmoteMemory@16' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_AllocahteRemoteMemory@8' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_GejtModuleBaseAddress@8' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_TerminatejbProcessByID@4' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'_CheckPirocessForString@8' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b'BACAIHJHUTVTWT[Zbadcecfcgchciclkrqsq}|~|' in content:
        detection += '🕴️' + ('Agent Tesla')
        Score = Score + 8
    if b'3/9;h~lo/0jcdibnch-~~l]1' in content:
        detection += '🕴️' + ('Agent Tesla')
        Score = Score + 8
    if b' / a n' in content:
        detection += '🕴️' + ('Ursnif')
        Score = Score + 7
    if b'ngTinC' in content:
        detection += '🕴️' + ('Formbook')
        Score = Score + 4
    if b'adminToolStripMenuItem_Click' in content:
        detection += '🕴️' + ('Formbook')
        Score = Score + 4
    if b'ngaySinh' in content:
        detection += '🕴️' + ('Formbook')
        Score = Score + 4
    if b'soDienThoai' in content:
        detection += '🕴️' + ('Formbook')
        Score = Score + 4
    if b'btn_Update_Click' in content:
        detection += '🕴️' + ('Generic Malware')
        Score = Score + 4
    if b')>-;8*#' in content:
        detection += '🕴️' + ('Agent Tesla')
        Score = Score + 8
    if b'hycdhyl{d' in content:
        detection += '🕴️' + ('Agent Tesla')
        Score = Score + 8
    if b'8SVWjnXjtf' in content:
        detection += '🕴️' + ('Formbook')
        Score = Score + 4
    if b'encryptionAesRsa' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'checkStartupFolder' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'checkdeleteBackupCatalog' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'appMutexStartup2' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'appMutexStartup' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'surprise.exe' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'(?:[13]\{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'checkdisableRecoveryMode' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'checkdeleteShadowCopies' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'7z459ajrk722yn8c5j4fg' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'sleepOutOfTempFolder' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'1qw0ll8p9m8uezhqhyd' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'2X28tfRmWaPyPQgvoHV' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'copyResistForAdmin' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'checkCopyRoaming' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'17CqMQFeuB3NTzJ' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'addAndOpenNote' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'appMutexRegex' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'sleepTextbox' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'appMutexRun2' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'randomEncode' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'checkSpread' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'copyRoaming' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'appMutexRun' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'spreadName' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'appMutex2' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'spreadIt' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'addLinkToStartup' in content:
        detection += '🕴️' + ('CHAOS Ransomware')
        Score = Score + 7
    if b'encrypted_key":"' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'[\%04i/\%02i/\%02i \%02i:\%02i:\%02i' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'0!0-070K0W0e0o0{0' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'606A6G6M6T6a6' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b';+;=;I;Q;i;' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'L$,#L$ #D$,' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'T$$#T$(#D$$' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'm0~0a2l2|2' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'5<5B5G5M5^5' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'5(5N5f5l5' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'K j@^+s`;' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'u PPj7UPQ' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'C`UVWj@_' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'u:E;l$(|' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'L$ !t$ j' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b't$Pf \\$V' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'W?PPUSPQ' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'\\$(X+D$$' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'[BckSp]' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'Remcos' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'CreateObject("WScript.Shell").Run "cmd /c ""' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b't]<*u?N' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'SUVWj7_' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'pth_unenc' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'StopReverse' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'fso.DeleteFolder "' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'while fso.FileExists("' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'GetDirectListeningPort' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'/sort "Visit Time" /stext "' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'wnd_\%04i\%02i\%02i_\%02i\%02i\%02i' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'time_\%04i\%02i\%02i_\%02i\%02i\%02i' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'fso.DeleteFile(Wscript.ScriptFullName)' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'9l$`~A' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b't$LVU3' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'tD;Ntr' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'VjxVVh' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'L$<jHY' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b's u&j@' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'D$$PuJ' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'u79|$$' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'_9l$Lt' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'SVWjGZ' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b';G,uBSV' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b't%<.t<G' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'^f9t$ s' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'I9t$4t+' in content:
        detection += '🕴️' + ('REMCOS')
        Score = Score + 6
    if b'SYSTEM\\CurrentControlSet\\ControlTerminal Server\\AddIns\\Clip Redirector' in content:
        detection += '🕴️' + ('AVE_MARIA')
        Score = Score + 5
    if b'select signon_realm, origin_url, username_value, password_value from wow_logins' in content:
        detection += '🕴️' + ('AVE_MARIA')
        Score = Score + 5
    if b'Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper' in content:
        detection += '🕴️' + ('AVE_MARIA')
        Score = Score + 5
    if b'A pure virtual function was called. This is a fatal error, and indicates a serious error in the implementation of the application' in content:
        detection += '🕴️' + ('AVE_MARIA')
        Score = Score + 5
    if b'cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q' in content:
        detection += '🕴️' + ('AVE_MARIA')
        Score = Score + 5
    if b'N^RV[\\6yeg' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'jVfc8\\@OeU' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'PqIIi4Zb>4' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'nj)r\\Rx?Jj' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'dt9q9<oDf7' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'8yi"V    Ww|8' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'Ydk{g(B7Hj' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'%\\4*<b"]q2-' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'\%M|+K|K28/,' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'WNPNLNENS.T' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b's\'EtEDW@ts~L' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'51=o>g7RxQj=' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'F* ($,"*&.!)\'' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'_t:lN+XBjRe\' ' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'0\/0?0F0b0s0z0' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'2 282?2K2Z2u2|2' in content:
        detection += '🕴️' + ('BadRabbit')
        Score = Score + 19
    if b'*ssfn*' in content:
        detection += '🕴️' + ('NexusLogger')
        Score = Score + 10
    if b'i>k__BackingField' in content:
        detection += '🕴️' + ('Habbo')
        Score = Score + 10
    if b'BCrbMasterKeyyptImbMasterKeyportKbMasterKeyey' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'SELSystem.LinqECT * FRSystem.LinqOM WinSystem.Linq32_VideoCoSystem.Linqntroller' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'SSystem.ELECT * FRSystem.OM WiSystem.n32_ProcSystem.ess WherSystem.e SessiSystem.onId=\'' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'\%USERPserviceInterface.ExtensionROFILE\%\\ApserviceInterface.ExtensionpData\\LocaserviceInterface.Extensionl' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'\%USERPserviceInterface.ExtensionROFILE%\\ApserviceInterface.ExtensionpData\\LocaserviceInterface.Extensionl' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'SELSystem.Windows.FormsECT * FRSystem.Windows.FormsOM WinSystem.Windows.Forms32_ProcSystem.Windows.Formsessor' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'SELESystem.ManagementCT * FRSystem.ManagementOM WiSystem.Managementn32_DisSystem.ManagementkDrivSystem.Managemente' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'SELSystem.Text.RegularExpressionsECT * FRSystem.Text.RegularExpressionsOM Win32_PSystem.Text.RegularExpressionsrocess WSystem.Text.RegularExpressionshere SessSystem.Text.RegularExpressionsionId=\'' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'KDBM(6' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'MSObject32' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'*wallet*' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'chromeKey' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'https://api.ip.sb/ip' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'\\Discord\\Local Storage\\leveldb' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<GetWindowsVersion>g__HKLM_GetString|11_0' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'nSystem.CollectionspvoSystem.Collections*' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'cFileStreamredFileStreamit_cFileStreamardFileStreams' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'\%USERPFile.WriteROFILE%\\AppFile.WriteData\\RoamiFile.Writeng' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'BCrstring.EmptyyptOpestring.EmptynAlgorithmProvistring.Emptyder' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'SELEMemoryCT * FMemoryROM WiMemoryn32_OperMemoryatingSMemoryystem' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'\\TeEnvironmentlegraEnvironmentm DEnvironmentesktoEnvironmentp\\tdEnvironmentata' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<DomainExists>b__0_0' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'GetDefaultIPv4Address' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<ListOfPrograms>b__8_0' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'ProldCharotonVoldCharPN' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'serviceInterface.Extension' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<AvailableLanguages>b__9_0' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<GetDefaultIPv4Address>b__1_1' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<GetDefaultIPv4Address>b__1_0' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'roSystem.Linqot\\CISystem.LinqMV2' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'Concat0 MConcatb oConcatr Concat0' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'BCrUnmanagedTypeyptDecrUnmanagedTypeypt' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'E3E8284EDCB98A1085E693F9525A3AC3D705B82E' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'7FD227EEE2F38A50CFD286D228B794575C0025FB' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'FB10FF1AD09FE8F5CA3A85B06BC96596AF83B350' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'A898408AA9A30B686240D921FE0E3E3A01EE91A5' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'93D9D319FF04F5E54F3A6431407A7B90388FDC54' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'1938FDF81D9EFE09E9786A7A7DDFFBD755961098' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'410D551BF9DC1F0CF262E4DB1077795D56EEC026' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'8C550EA96A693C687FFAB21F3B1A5F835E23E3B3' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'28F794B091ED92F57BFC80EA32B18AF3A8183ADB' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'2A19BFD7333718195216588A698752C517111B02' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'99086C63443EF4224B60D2ED08447C082E7A0484' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'718D1294A5C2D3F3D70E09F2F473155C4F567201' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'1A79939AEFF161E557D02CB37CD9A811ABCAF458' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'6353B688B99A3543932AA127DAA0E48FBC646BBD' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'scannerArg' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'GatherValue' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'browserPaths' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'String.Quarantine' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'ChromeGetName' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'FileStream.IO' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'String.Replace' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'string.Replace' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'FileScannerRule' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'IRemoteEndpoint' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'ReadContextValue' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'ReadContextTable' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<DomainExists>b__2' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'ReadMasterOfContext' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'<DomainExists>b__0_1' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'NordVpn.exe*MyGToMyGkens.tMyGxt' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'NoGetDirectoriesrd' in content:
        detection += '🕴️' + ('RedLine stealer')
        Score = Score + 4
    if b'nauu652pc41.dll' in content:
        detection += '🕴️' + ('BumbleBee')
        Score = Score + 4
    if b'sc delete K9-Defender' in content:
        detection += '🕴️' + ('AntiK9D')
        Score = Score + 46
    if b'VmKnyogV~w}aytb~ggZycnk|s' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'b)&\'$#vcm}`k*-*+Pxxy}d0evz<tthlkSDPLMMS' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'BJZMYN^H^GEREUMUNRWWBLenfv}' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'>>4<*:|.:24>!$tz+\'$ia>9$\'7' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'lV YlV YlV YlV YmV Ye.' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'_dF|xug@p}lU{Oz\}uill' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'+4,1#m%9+o:/9(: &#n' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'\\gCtbT{\{n~`mJwnxcg' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'DSKUAWU{^DGDY^K' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'T~pwx@t}pjxX~xl' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'DgycurfzssNptpyb' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'GPHVBTVx}hFPbAX_V' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'vMn^NPWQQEWcFZUR[Z' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'vuhZa`.dvj' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'DXPL]KLRWP' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'wdkwld,fth' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'`cwTqgreaz' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'8?97=5*u09:' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'1\'70(%4l(4*' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'`vdjjkl~\'lgf' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'*?=\'=;#?m\'9%' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'2$6889>5u>54' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'NJCEOYALBY\\@D' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'YmV YRichlV Y' in content:
        detection += '🕴️' + ('Satan')
        Score = Score + 9
    if b'b~uhlpdr!kui' in content:
        detection += '🕴️' + ('Zeus')
        Score = Score + 9
    if b'E#+E/^ZY' in content:
        detection += '🕴️' + ('EnigmaProtector')
        Score = Score + 1
    if b'emRoot%' in content:
        detection += '🕴️' + ('Maudi')
        Score = Score + 9
    if b'esi-WS' in content:
        detection += '🕴️' + ('Lazarus')
        Score = Score + 9
    if b'reg delete' in content:
        detection += '🕴️' + ('Reg.Deleter')
        Score = Score + 12
    #Newer Detects
    if b'format C:' in content:
        detection += '🕴️' + ('C.4Mat(formats the C: drive, erasing all data on it aka erasing windows, your user, your files, and programs)')
        Score = Score + 46
    if b'shutdown' in content:
        detection += '🕴️' + ('windows.shutdown(shuts down windows)')
        Score = Score + 7
    if b'move C:\\Windows' in content:
        detection += '🕴️' + ('windows.system.mover(moves C:\\Windows to somewhere aka making windows die)')
        Score = Score + 45
    if b'schtasks /delete' in content:
        detection += '🕴️' + ('windows.tasks.automatic.delete(deletes a automatic task this can stop important tasks)')
        Score = Score + 16
    if b'schtasks/delete' in content:
        detection += '🕴️' + ('windows.tasks.automatic.delete(deletes a automatic task this can stop important tasks)')
        Score = Score + 16
    return {"Score":Score,Score:detection}

class scan(object):
    """Scan a file's Bytes for Malware!"""
    def __init__(self, Content):
        super(scan, self).__init__()
        data           = _cscan(Content)
        self.Score     = data["Score"]
        self.Detection = ','.join(data[self.Score].split('🕴️'))
        self.Content   = Content
