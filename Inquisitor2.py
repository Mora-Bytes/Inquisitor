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
    if b'Vm0wd2VFNUdiRmRXV0doVlYwZDRXRmx0ZEhkVU1WcDBUVlpPV0ZKdGVGWlZNbmhQWVVaS2MxTnNXbFpOYm1oUVdWZDRTMk14WkhGUmJVWlRWakZLU1ZacVFtdFRNVWw0Vkc1T1lWSnRhRzlVVjNOM1pVWmFkRTFVVWxwV01ERTFWa2QwYTFkSFNrZGpTRUpYVFVkU2RsWkdXbHBsUm1SelYyMTRVMkpJUWpaV2EyTXhWREZaZVZOclpHcFNiV2hoV1d0YVYwNUdVbkpYYkhCc1VtMVNlbFl5TVRSVk1ERkZWbXh3VjFaRmIzZFdha1poVTBaT2NtRkhhRk5sYlhob1ZtMTBWMk5yTVVkalJWWlRZbGhTV1ZWcVJrdFRWbFowVFZoa2FGWnNjSHBaTUZwM1ZqRmFObEpZWkZwbGEzQklWbXBHVDFkWFNraGxSazVYVWpOb2IxWnRNWGRVTVZWNVVtdGthbEp0YUhOVmJUVkRZekZXZEUxV1RrNVNiRVkwVmpJeE1GWlhTa1pqUldSWFRXNVNNMVpxUm1GU2JVNUZWR3hrYUdFeGNGUlhiRlpoWkRGS2RGTnJaRlJpVjNoWVZGY3hiMWRzV25KWGJHUmFWbTE0VjFSV2FFOWhiRXAwVld4c1dtSkhhRlJaTVZwVFZqSkdSbFJzVW1sU2JrSktWa1phVTFVeFdYZE5XRXBxVW01Q1dWWnJWVEZrYkZweFVtdHdiR0pWV2twVk1qRkhWVEZLV1ZGcmJGZGlWRVkyV2xWYWExWXhUblZVYkZKcFZqTm9kMVpYTURGUk1WcFhWMjVLV0dKWVFrOVdiWGhoWlZaU1YxWnRkRmROVjFKSldWVmFjMWR0UlhoWGFrNWFaV3RhV0ZwRlpGZFNiVkpJWlVkc1UySnJSak5XTW5SWFlqSkZlRmR1U2s1V2JIQnhWV3hrVTFZeFVsaGpSbVJZVW14d01GbDZUbTloYkZwelkwaG9WMUl6YUdoWlZscHJVbXN4VlZWc1pHbFdSVmt5VjJ4V1lXRXhXWGhUYmxaVVlrVktXRmxyVm5kV1ZscEhXVE5vYVUxV1ducFdNV2h2VjBkS1dWRnVUbFpoYTBwWVZGUkdVMVl4WkhSa1JtUnBWbGhDU2xac1pEUlpWbGw1VWxob1dHRXphR0ZhVjNSaFpXeGFjMWRzVG1waVJUVXdXbFZrYzFVd01IaFNhbHBYWWxSRk1GbHFTa3BsUm1SWllrWlNhRTFZUW5oV1Z6RTBaREZzVjJKR1ZsTmliVkpZVlcxNGQyVkdWWGxrUjBab1RVUkdSbFp0ZUd0V01VbDZZVVpvVjFJemFHaFpla3BQVWxaa2MxcEdaRTVOYldoMlZtMHhkMUl4YkZkWFdHaFVZbXhhVlZsWWNITlhSbEpWVW10MFZsSnNjRWhXYlhocllUQXhXRlZyYUZkTmFsWlFWbTB4Um1WV1ZuTmhSbkJwVW01Q2IxWlVRbUZXYlZaV1RsWmFVRlp1UWxoV2ExWktUVlprVjFadFJscFdiVko2VjJ0V2MxVnRSWGxoUm1oYVZrVmFNMWxWV25OT2JFcDBaRWQwVTJFelFqWldha2w0WXpGVmVGZHJaRmhpUjNoWVdXeG9iMkZHYkhGVGExcHNVakJ3U0ZZeWN6RldNVnB6WTBaV1dGWXpVbWhhUkVaYVpVWmtkVlZ0ZUZOaWEwcDVWa1phWVZsWFZsZGFTRXBYWVd0S1YxUlZVa2RXTVZKellVaE9XRkl3VmpSWk1HaExWakZhUm1ORmVGWk5WbkJJV1RKNFlXTXhjRVpPVjJob1RWWlplbFp0TUhoa01VbDRWRmhzVlZkSGFGWlpiWGhoVm14c2NscEdUbXBTYkZvd1drVm9hMVl4U25OalJXaFhZbGhvY2xacVNrZE9iRXB6WVVaa2FWSXlhREpXYlhCTFV6RmFXRk5yWkdGU2JGcFlWRlJHU21Wc1dsVlNiVVpYWWxaYVdWWnRkSE5XVjBwSFkwaENWMkpIYUVSV2FrWmhWMFV4U1ZwRk9WZGlSM2N4Vmxjd01WTXhVWGhhUldScVVqQmFhRlpxVGxOaFJscHlWMnhhYTAxV2NGcFpWVnB2VlRBeFZtTkZjRmhXTTFKb1ZrUkdVMk14WkhOaVJrcG9UVEpvV1ZkWGVHOWlNazVYWTBaYVYxWkZXbFZWYlhSM1pXeGtjbHBGWkZaTlZuQXhWVmQ0WVZkR1dqWlNXR1JoVWtWYWVsWnFSbXRrVmxaeVRsWmtiR0pZYUZkV2ExcGhZVEExU0ZaclpGZGlSMmh4Vld4Vk1WZEdiSE5XYm1SWFRWWktlbFp0TURWV01ERldZa1JhV2xaV2NFUldha3BIWTJ4a2RGSnRSbGRXYmtKUlYydGFZVll5VFhoalJXaHBVbXMxY0ZVd1ZrdFpWbHAwWlVkMGEwMVZiRFJaYTFwclYwWmtTR0ZHWkZwaVdGSXpWbXBHYzJOc1duVmFSbWhUWWtad05GWnJZM2RPVmxwWFUyNU9hbEpzY0ZkV2FrNXZZMnhzV0dNemFHcGhlbFpYV1ZWYWExUnRTblJoUm14WFlsaFNhRmRXV2twbFJuQkpWbXhLYVZJeFNuWlhWbEpIWkRGU1YxZHNWbFJoYkVwdlZGZHpNV1ZzYTNkV2JUbFdVbXhzTlZsVmFFTldNa3BJWVVWU1YwMVdjR2haTVZwUFYxZEdTR1JGTlZkaVdHTjNWbXhTU2sxV1ZYaFhibEpVWW14YVUxbHNWbUZYUm14MFRsVk9WRkpzY0ZkV01qVnJWVEpLUjJOR1dsZGlXR2gyVm1wQmVGSldXbkpqUm1oWFRURktXRlpHV210U01WbDRWRzVHV0dKWGFFOVVWRUpMVjFaa1YxcEVRbFJOVjFKSVYydGFhMWxXU2xkalNFNVhZbGhvVEZwV1duTldiR1J6Vkcxb1YwMUlRa2hYVkVKaFlqRmtSMWRxV2xOV1JVcG9WV3RXZDFWR2JEWlNiR1JxVFZad2VsVXllR3RWTVZwMVVXcEtWMDFYVVhkWFZscHpWakZrZFZSc2FHaE5iV2g2Vmxkd1QxVXlUa2RXYmxKc1UwVTFUMVJXV2t0bGJGcFlaRVU1VjAxRVJubFpNRnBoVmpKS1dXRklXbGROYm1ob1ZXMTRhMk50VmtkalIzaG9UVEJLVWxac1VrZFpWbFY1VkZoc1ZXRXhjRkJXYWtwdlkwWldkRTVWVGxaTlZuQjRWVzE0VDFWck1YSldhbEpYVW5wV1ZGWnFTa3RTTWs1SFVXeGthVlpGV2pKV2JURTBZekpPYzFwSVZtRlNNMEpVV1d4b2IwNVdXbkZUVkVaYVZqQndTRlV5TlU5V01rWnpVMnhzV2xaRmNGTmFSRVp6VmxaR1dXRkdaRTVXYmtJMFZteGtORmxXVW5SVGJsSm9VbnBzV0ZSV1duZGhSbFY1VFZaa1ZGSnNTbmxYYTFwdllWWk9SbE5zYkZkV00yaFlXa1JLU21WR1pIVlRiRnBvVFd4S1dWWkdaSHBsUlRWSFYyeG9UMVpZVWxoVmFrSjNVakZWZVdWSE9WZE5hMXA1Vkd4b1lWWnRTbGxoUjJoWFlrWndVRmt4V2tka1IwcEdUbGRvVGxkRlNscFdiWFJoV1ZkSmVGTlliRk5pUjFKV1dWUktVMWRXYkhOV2JVWmFWbXh3ZVZadE5XdFdNVXB6WWtST1YwMXVhSEpaVnpGTFUxWkdjbHBHYUdoTldFSlZWbTF3UzFJd05YTlhiR3hvVW0xU2IxbFVTak5OUm1SWlkwVmtXR0pXUmpOVVZscHJXVlpKZWxGc1VsZGlXRkl6VmpKNGExWXhWbkphUjNST1lrVndObFpxU2pSV01WcElVMnRhVDFkRldsWldiWGgzWVVad1YxZHVUbGRpUjFKNVZERmtiMVV3TVVkWFZFSllWa1ZLZGxsVVJtdFNNV1JaWTBkb1UySldTbGRXYlRCNFZURmFSMkpFV2xOaWJWSlVXV3hXZDFOV2EzZFhiRTVXVFZkU1IxVXllRXRXTWtwVlVsUkNWMVpGV2t0YVZscGhZMnh3UjFwSGJHaGxiRm95Vm14U1EyRXhWWGhYYms1V1lrZG9jbFZxUW1Gak1XeHlXa1JTYkZac2NGbGFWVlUxVmpBeFYyTkljRnBOUm5CMlZtMXplR1JXVmxWUmJHUm9ZVEJaTUZaWGNFdFVNVXAwVm10a1lWSXllRmxWYWtwdlZHeFplRlZyZEU5U2JYaFpWa2MxUzFReFduUmhSemxXWVd0d2RsWkVSbUZrUlRGVlVXczVWMkpJUVhkWGExWnJVakZrYzFkdVRsZGhiRXBZVlcweGIyUnNXbkphUlhScVlYcFdXRmxWV210VWJFbDRVMnhXVjJKWVVtaFpla1poVmpGT2RWVnNUbWxTYkhCUVZtcENWMU14WkhOYVNFcFhZbFZhYjFSV1drZE9WbFY1WkVkMFYxSXdjRWxaVlZwdlZqSkdjazVXVWxWV1JWcDZWbTE0YTJSR1NuTmFSMmhzWWtad2FGWXhVa05aVm14WFZXNVNWR0pyTlZWWmJGSnpWMFpzY2xkcmRGSk5XRUpYVmpJeFIxZEdTbkpPV0d4WVlUSlNkbFpVU2t0VFZrWnpZa1pvVjAweFNtOVhWRWw0VlcxV1IxcElWbFpoZWxaWVZXMTBkMVpzV2tkWGJVWnJUVlUxU0ZadE5WTmlSa3AwVlcwNVYySllVak5XTW5oWFYwZFdSazlXWkZkaVIzY3lWbXRhYjJJeGJGZFRhMXBZWWtkU2FGWnRlRlpsUmxsNFYyeE9hazFWTlRCWmExcHJWakZLYzJFemFGZGhhMXB5VkZWYVdtVldTbGxoUm1ocFlrVndWVlpxUW10aU1rNVhWbTVTYkZOSFVsbFZiVEUwWld4c1ZsZHJPVmRXYTNBd1dsVm9kMVl3TVhGU2EyaFhZV3R3VEZWcVNrOVRWMHBIWVVkb1RsZEZTalZXYlRGM1V6RkpkMDVZVGxoaWEzQlpXV3RrVTFkR2JISmhSVTVPWWtad1dsa3dWbXRXVlRGeVRWUlNWazF1YUhwWlZscExZekpPU1ZGc1pFNVNiSEJOVm1wQ1lXRXhXWGhqUlZaU1lsaENiMXBYZEdGWFZtUlZVV3hrYVUxcmNFaFdSM1JyWVd4T1JrNVdhRnBXTTFKb1dWVmFWbVZHWkhWYVJtUnBVakZLTlZkclZtRldNa1pYVjJ4c1VtSklRbGhVVjNCWFRURldjVkp0ZEZOTlYxSmFXVEJhUzJGRk1IaFRiVGxYWWxob2NsWlVSbE5TTVZwMVVteE9hRTB4U25oV1JtUXdaREZPUjFwSVNtRlNlbXh2Vld4U1IxTnNWbGhqUlRsWFRXdFdORmt3V205WGJVWnlZMFYwWVZac2NGQldNV1JIVTBkT1IxUnNaRTVXV0VKMlZtcEtOR0V3TVVkaVJtaFVWMGRvY0ZVd1ZURlhSbXh6Vm0xR1YxSnNjREJhVlZZd1lrZEtTRlZ1YkZkV00yaFFXVlZhWVdOdFRrbGlSbkJvVFZWd1ZWWnRjRXRUTVZwWFYyNU9hRkp0VW05VVZtaERZakZhZEUxWWNFNVdiSEJZVjJ0b1QyRkdTWGxoUnpsVlZsZE5NVlJ0ZUdGamJIQkZWV3h3VjJKRldUQldNblJYV1ZaUmVGZHVUbXBUUlZwWFdXeG9VMDB4V2tWU2JFNVhZa1phZWxkclZURldNa3BKVVd4a1YxWkZXbFJWYWtwSFkyc3hWMWRzYUdoaE1IQlpWbTF3VDFVeVJrZGlTRXBZWVROU2NsVnFRbUZUUmxaWVpVZDBWV0pGY0RGVlZtaDNWakpGZVZWVVFsZE5ha1pUV2xWYWEyTXhXbk5UYld4WVVtdHdVVlp0TVhkU01VMTRXa1prWVZKdFVsaFphMlJUVkRGV2RHVkZkR3hpUmxZMFdWVmpOVll4U1hkalJYQldWak5vY2xacVNrdFdWa3AxVjJ4a2FFMVlRalpXYlhoaFVqRmtXRkpyYUd0U2F6VlBWbTAxUTFOR1duTlpNMmhQVWpCc05WVnRkR0ZVYkdSR1kwVTVWazFIVW5aV01GcFhaRWRXUm1SR1RsTmlXR041VmxjeE1FMUdWWGxTYWxwcFVtMW9ZVmxVU2xOVFJscFZVVmhrYTAxVk5URlhhMXByWVZaYVJsWllaRmhoTVVwRFdsVmFTbVZHY0VkaVIyeFRUVEpvVlZkc1kzaE9SbVJIVjJ0a1lWSkZTbUZXYkZKSFUwWmFkRTVXVG1oTlZYQXdWbGN3TlZZeVJuSlhiV2hoVm14d1lWcFdaRk5TVmxaelkwWmthRTB3U2tsV01WcHZaREZKZUZkWWFGUmlSMUp4VlRCV2QxbFdVbGhPVnpsT1RWWmFlRlZ0Tld0V1JrbDNZMFZvV0dFeGNISldSM040WkVkR1JrMVdaR2xXUlZZelYxWmplRll4U25KT1ZscG9VbXMxV1ZWcVNtOVdiR1JZVFZSQ1dsWXdOVWhXYlRWTFYwZEtWbGRzYkZkaVZFVXdXbFphYTJOc1pISlBWMmhwVmxoQ1NsWnNaSGRSTVZwWFYyNU9XR0pYYUdGWlZFWjNZVVpzTmxOck9WUldNRnBJVjJ0a2MxZEdTWGxhZWtwWFlsaFNjbHBYTVZkU01YQkhXa1pPYVdKR2NGcFhWM1JyWWpGa1IxVnNWbE5oTTFKUFdXdGFkMDFHYTNkV2FrSlhVbFJHVjFrd1VrTldNVmw2Vlcxb1dGWnNjRXhaZWtaUFpFVTVWMVpzWkdsV01taEdWbTB4TkZsV2JGZFRXR2hoVTBVMVZsbHNhRU5VTVZwMFpVaGtUMkpHY0RCVVZsSlRZVVV4V0ZWcmJGWk5ibEpvVmtSR1lXTXhaSE5oUm5Cb1RXeEtNbGRyWkRSV01rMTRXa2hPWVZKdGFGUldhMXBoVjFaWmVXUkhSbWxOYTFwWVZUSTFVMVZHVGtobFJtaFhZbTVDUTFwVldtRlNWa3AwVW14a1RsWlVWalpXYWtwNlRsWlplRmR1U21wU2JWSllXV3hvUTFWR2JIRlRiR1JxVFZkU1dsZHJaRWRWTWtwWFUyeFdWMkpVUlhkYVJFRjRVakZhZFZWdGVGTk5SbkJYVjFkNFYyUXlWbGRWYkdSV1lrZFNXRlJXV25kbGJGVjVaRVJTV0dKV1dubFdNblJ2VjIxV2NtTkZkR0ZXTTJnelZUQmtTMUl4VW5OYVIyaE9UVVZ3VjFadGNFZFpWMFYzVFZWa1ZWZEhlRlpaYTJSVFkwWlZkMWRyZEZWTlZtd3pXVlZXVDFaVk1WaGxTR3hYWWxob2NsWkVSbUZrUjFaSllrWmthVmRHUmpOV2FrbzBXVlphVjFOdVNtbFNNRnBZVm0xNGQxZFdXblJOVkZKYVZqRktTRlp0TlZkV1IwcEhZMFU1V21KVVJuWlZNRnByWTJ4V2NscEdVazVpUlhCSVZrZDRZV0V5Um5OVGJGWlhZbFJzWVZaclZtRk5NVmw1WlVad2JGSnRkRFpYYTJRMFZUSkZlV1I2UWxkTmJsSm9XVlJHWVdSR1RuVlRiR2hwVWxSV2FGZFhkR3RpTVVwSFlUTmtXR0pyTlhGVVYzUmhVMVpSZUZwRVFsWk5hM0JZVlRKNGMxWXlTa2hWV0dSVlZsWndZVnBFUVhoV2JGcHpXa2RzVTAxVmNHOVdNVnBUVWpGc1YxcEZaRmhoTW1oelZXeG9RMk14V25SbFIwWnNZa2QwTTFZeWVHdFdNREZXWTBad1ZsWXphRmhXTUdSR1pVWk9jbUZHY0d4aE0wSlZWbGN4ZWsxV1dYaGFTRkpyVW1zMVQxbHRNVzlXYkZsNFdUTm9UbEpyY0RCV2JYUnJWMGRGZVdGSVRsWmhhMHBvVmxSR1UxZEhVa2hTYlhocFVteFpNRmRXVm1wT1ZtUkhVMWhrV0dKdGVGaFVWelZ2WTJ4a1YxZHNjR3hpUmxwNFZrZDRhMVJzU25WUmJGWllWMGhDU0ZkV1pFOVdNVXAxVkd4V2FHVnNXbFZXVjNCUFlqRmtSMWR1VW10U00wSnpWV3BDYzA1R1dYaGhTRTVYVFd0d2VWUnNXbk5XTWtWNFYyMW9WMDFHY0ZSV01GVXhWMFU1V0dOSGJGTk5NbWhoVm10YVlWbFdVWGhYV0dST1ZtMVNWVmx0TVRSWFJsSllZMFZhYTAxV2NGWlZiVEZIWVRGYWNsZHVjRnBOUm5CeVdWWmFZVkpzWkZsalJtaFlVMFZLU1ZaWWNFZFhiVlpIWTBWc1YySkdXbkJWYWtwdlpHeGFSMVZyWkZSTlYxSklWakowYTFkSFNraFZia3BWVm14d2VsUnJXbUZYUlRWV1QxWm9VMDFJUWtwV2JHUTBZekZaZVZOclpGUmhNbWhZVkZWYWQxbFdjRmRhUm1SVFRWaENTRmRyWkhOV01XUkdVMnR3VjAxV1NrUldha0Y0VWpGd1NWVnNaR2xoTTBKV1YxY3dNVkV4V1hoaVJtaHJVakJhVjFWdE1UQk9WbkJXV2tSQ2FHRjZSbGhWTWpWelZsZEtSMk5JU2xkV1JVWXpXbFprUjFJeFduTmFSMnhZVWpKb2RsWnFSbUZaVjAxNFYxaG9XR0pIZUc5VmJYaGhZMFpXZEU1VlRteGlSbkJaV2xWa1IxWkZNVmRXYWxKWFRWZG9jbGRXV2t0amF6VlhWMnh3YUUxWVFtOVdSbFpoWTIxUmVWSnJXbXRTTW5oVVZGVm9RMU5zWkhOV2JVWnBUVmRTU0ZkclZuTlZiVVY1WVVkR1dsWkZXak5aVlZwM1VqRmtjbHBIY0U1aE0wSkpWMVpXWVdFeFZYaFhhMlJZWWtoQ1dGbHNVa1prTVZwMFRWWmtVMDFWTlZwWlZXUkhWa1pLY21OR1ZsaFdNMUp5V1dwR1lWSXhXblZVYkdScFlsWktWbFp0TVRSa01sWlhWMWhzVGxaWFVsaFpXSEJIVmpGc2NsVnJPVmRXVkVaWVdUQmtiMVl5UlhsVmEzaFdZbFJHVUZWdGN6VldNV1IwWWtaT2FFMHdTbUZXYlhoVFVURnNWMkpHYUZWWFIyaFlXVzEwZDJGR1ZuUmxSMFpxVW14d2VsWlhlR3RXUmtwelkwaHNXRmRJUWtoV1YzTjRWakZrZFdOR1pFNVdNbWcyVm0wd2VGSnRWbk5XYms1aFVtMVNiMVJXV25kVVZscFZVVzFHYWsxc1NrbFdiWFJoVlVaYWRGVnVRbFppV0ZJelZHeGFZVlpXVGxsaFJrNU9WbXR3TmxacVJtOWpNVnB6VjJ0YWFsSnRhRlpXYm5CWFZrWndTR1ZHWkZkV2F6VjVWMnRhYjFVeVJqWldXR2hYVmtWc05GcEVSbUZTTVU1elZteGthVk5GU2xwV2JUVjNVVEExUjJOR2FFNVdiVkpVVkZaa1UwMVdWWGxsUnpsb1ZqQndXRlV5ZUhkV01rcFZVbFJDV0ZadFVsaFpla1ozVTFaT2MyRkhiR2xXYTNCYVZtdGFWMVV4UlhkT1ZtUmhVMFZ3VjFsclZURlhSbEpXVld0a1RsWnRlRmRXTWpBMVZqQXhjbGR1YkZaaVIyaDJWbTB4UzFaV1NuTlZiRnBwVmtWYVRWWlhjRWRXTWxKSVUydGthRkpyTlU5WmJHUnVaVlphZEUxVVFscFdNRm93Vm0xMFlWUXhXbGRqUmtKWFRVWlZlRmt4V2xkak1XUjFXa2RzVGxac2NEWlhWbFpoVkRGYWMxTnVUbXBTUlVwV1ZtMHhVbVF4V2tWU2JVWnJWbXRhZVZkcldtOWhSVEZXWTBaV1dGWnNjR2hWZWtwT1pVWmtkVkpzYUdsU01taDJWa1prZW1WRk5VZFhia1pVVjBkb1ZWUldXbmRYUmxWNVRsVjBhRkpyYkROV01uaFRWakpLVlZaclRtRldNMmhvV2tWa1UxTkhVa2RYYld4WFlraENXbFl4VWtOV01XeFhWVmhvV0dKcmNIRlZiRkp6Vm14YWNWUnRPVlZTYkVwWVZqSXhSMkZzV25KWGJuQlhVak5vV0ZaSE1VWmxSbVJWVW14a2FFMXNSak5YVjNCSFdWWk9SMVJ1VmxWaVIyaHdWVzE0ZDJGR1pGaGtSM1JwVFd4S2VsbHJXbUZYUjBwMFZXeG9WVlpzY0doYVYzaHJZMnhrZEdSR1drNWhNMEpKVjFSQ1UxbFdXWGxUYkZaU1lXeEtWbFpzV25kbGJGbDNWMnM1YW1KSVFraFhhMlJ2WVZaS1dWRnRPVmROVm5CeVdsZHplRll4V25KYVJtUllVak5vZWxaWGVGTmpNVnBIVld4b2FtVnJXbFZXYlhoSFRrWlplVTVYZEdoU2EzQldWVzF3UTFkc1dsZGpTSEJYVFVad1lWcFhlRmRqTWtaSFZteGtWMkpyU2xwV01uUlhXVlpSZUZwR2FGUmhNbWhVV1d0Vk1WZFdWbk5XYm1SWFZteHdlVll5ZUd0V01ERllaVVpzVjFZemFISldNRnByVTBkV1NWUnNXbWxpYTBvMlYxUkNZVlV4WkVoVmEyaFRZbGhvY0ZWcVRsSmxiRnB4VTFSR1ZVMVdjREJWTW5oaFYwZEtkR1ZHWkZWV2VsWlRXa1JHWVdSRk1WWmtSbVJYWVROQ05sWnNZM2hTTVZWNFUyeGthbEpHY0ZsWlZFWmhWakZ3Vmxkc2NHeFNiRm94VmxjeE1GVXdNWFZoUm14WVZteEtTRmt5TVZkV01XUjFWVzEwVTAweFNsQldWekI0VGtaa1YxWnVVazlXYXpWWVZXcENkMlZXYTNkaFJXUlhZbFZXTkZZeWNFOVhSbHB6WTBaU1YwMUdWWGhXYlhoVFkyczFXR0pHVG1sU00xRXhWbTE0WVdGck1WZFZXR2hYVjBkb1ZWbHRkSGRYVm14eVdrUlNXRlp0ZUZaVmJURkhWR3N4VjJOR2JGcGxhelYyVmxSS1MxTkdWbkZTYkdScFYwZG9iMVpyWkRSWlYwMTVWR3RrVTJKSFVsaFphMVozVkZaYWMxa3phRmROVlRWSVZrYzFTMWxXU1hsbFJsSmFZVEZ3TTFwRVJtdFhSVEZWVVd4U1RsWllRalpXYWtadll6SkdjMU5zVm1sU2F6VldWbXBPVG1WR2NGaGxSM1JxWWxWYVIxUXhXbmRXTWtWNlVWaG9WMVp0VGpSWmFrWmhWakZrZFZWdGFGTldhM0JYVm0xNFlXUXlWbk5oTTJ4T1ZsZFNWVlp0ZUV0bGJHdDNWMjEwYUZacmNIcFpWRTV2VmpKR2NtSXpaRnBoYTNCSFdsVmFhMk14WkhKT1ZtaFRZVE5DV1ZZeFdtdE5SMUY0V2taa2FWSnRhSEpWYkdoVFl6RnNjbGR0Um14V2JHdzFXa1ZrTUZkR1NuSmpSRVpXVmpOU2VsWXllR0ZXTWs1SlUyeGtVMDB5YUdoWGJHTjRVakZLVjFOdVRtRlNNbmhaVlcxMGQwNVdXWGxsUjNSc1lYcEdXRll4YUhOV1YwVjVaVVphV21FeGNHaFpNRnBYWTFaS2NtUkdaRk5pVmtwYVYyeFdhMUl5UlhkTlZtUnFVbTFvV0Zsc1VsZFZSbHAwVFZWMGFtRjZWbGhaVlZwcllWWmtTRm96Y0ZoaVJuQm9WMVphYTFKck5WZGhSazVwVWpGS1ZWWnRkRmRaVms1eldraE9WMkpIVWxoVVZscDNaV3haZVU1V1RsZGlWWEI1V1RCYWExWldXalpXYmxwV1lXdGFNMVZzV2t0amJWSklaRVpPVjFKc2NGcFdiWGhyVGtkRmVGZFlhRmhoTWxKWldWUkdZVmRHVWxkWGJtUnFZa1pLVjFkclZURmlSa3B5VGxSR1YxSXphR2haVm1STFVtMU9SMU5zWkdsWFJVcEZWakZhWVdFeFNYaFdiazVZWWtad2NGVnFSa3RWVmxwMFRWUlNWMDFFVmtoV01qVlRWR3hhUmxOdE9WcFhTRUpJV2xaYWNtUXhaSFJrUm1ocFZsWlpNRlpxU1RGWlZsbDRVMnRhV0dKcmNGZFpWM1IzVlVaV2RHTjZSbGROV0VKSldWVmtiMVJ0Um5SYU0zQlhZbGhTYUZaVVJrcGxSbFpaWVVab2FXRjZWbmhXVjNoclRrWmFjMkpJVG1oU2VteHdWRlphUzFkV1VuTlplbFpYVWpCd1NGa3dWbUZXYlVwVlVWUkdWMkZyUmpSWk1uaHJZekpHUjFkck5WZE5iV2N5VmpGa01GbFdUWGhUYms1aFUwVTFjRlZ0TlVOaU1WSlhWMnhrVDFKc2NGbGFSV1JIWVRBeFZrNVZaRlZXYkhCb1ZsVmFXbVZzUm5OVmJIQlhVbFp2ZVZkc1ZtRlpWMUpHVFZWc2FGSXpRazlXYlhSM1RsWmFSMWR0UmxwV2JWSkpWVzF3WVZVeVNraFZiRnBYWWxob00xbFZXbUZXYkdSeldrWm9VMDFXY0V0V2FrbDRUVVpTZEZKWWNGSmhNbWhZV1d0a1VrMUdWalpTYkhCclRVUkdXbFpIZUZOaFJUQjVZVVpzVjJKVVJUQlZla1pMVWpGYWNWZHNVbWxTVkZaWlZrWmFiMUV4VG5OWGEyaE9WbnBzVjFSWGRGcE5iRnAwVFVSV1dGSnNiRFpaVlZwdldWWktSbEpxVWxaaGExcFlWakZrUjFOSFJrZFViR1JYVW14dmVWWnFSbXROUmxsNVZWaHNWMkV5VW5CVk1GWjNZakZXY1ZSc1RsaFdiWGhhV1RCV2ExWkdTblJsUm5CYVRVWmFjbFl3WkV0U01rNUhZVVp3VGxKcmNGRldiVEY2WlVaSmVWUnJaR2hTTUZwVVdXeGFTMVJXV2xWUmJVWlVUV3N4TlZWdGRHdFdWMHBJVld4U1dtRXhjR0ZVVmxwaFpFZFdTRTlYZEU1V1Zsa3dWbXhhYjJNeFdsaFRia3BQVm14d1dGUlZaRk5XUmxwMFpVaE9hMUl4U2tkYVJWcGhWR3hhZFZGcVVsZFdSVzh3VmtSR1lWSnJNVmRhUm1ocFVtNUNXRlp0Y0U5VmJWRjRZa1pXVWxkSGFGbFZiWGhoWlVaV1dHVklaR2hTVkVaWVdUQmFSMWRHV25OVGEwNWhWbGRTVUZwRldsTmpiR1IwWWtaT2FWTkZTak5XYlhCRFZqRk5lRk5zWkZoWFIyaFpXV3hvVTFaV1VsZFhibVJZVm14V05WcEZXbXRXTURGeVkwVndWbFo2VmtSV2JURkxVakZPY2xWc1ZtaE5XRUo1VjFSS05GbFhVa2RUYmxKcVVsUldXRlJXVm5kVGJGcDBaVWR3VGxac1ZqUldiWFJyVjBaa1NHVkhPVlppVkVaMldWVmFZV05XVW5SUFYyaFRZbXRLV2xkc1ZtRmhNVkY1VTJ0YVdHSnRlRlpVVm1SVFRURnNWMWR0Um1waVZUVklXV3RhYjFZeFNsWmpSemxZVmpOQ1NGWlhNVmRTTVhCSFlrZHdVMkpJUW5kWFZsSkhaREZaZUZkdVVtdFNiVkp5VkZaYWQxTkdhM2RXYkdSV1RXdHdNRlpYZUZOWGJVVjVZVVZTVmsxV2NGUlpla1ozVTFaU2MxWnRiRk5XUmxwSlZteGtOR0l5VFhoWFdHeFRWMGRvY1ZVd1duZFpWbkJZWkVkR1ZVMVlRbGhXTWpGSFlXc3hjbGRyYkdGU1ZuQlFXV3RrUzFJeVRraFBWbVJPVm01Q2VWZHNaSHBsUmxsNFZXeHNhRkl3V2xWVmJGcDNWbXhrVjJGSVpHcE5WbkJZVm0wMVIxVXlTbFpYYkZaWFlsUkZNRlpxUm10amJGWnlWR3hrYUdWcldrZFdWekUwWkRGYWMxZHVVbWhUU0VKWVZGVmFkMkZHVm5STlZYUlRWbXhLTUZWdGVFOVZNV1JHVTJ4YVYySllRa1JYVmxwU1pWWlNXV0pHVG1oTmJFcFhWMWQ0YTA1R1pGZFdiazVYWW0xU1QxbHJXbmRsYkdSeVlVZDBWMUpVUmtaV2JYUnJWbFphYzJOSVNsaFdiSEJRVlcxek1WWXhaSE5qUjJ4VFlUTkNXbFl4VWtkWlZsbDVWRmhzVTJFeWFGRldiRkpYVmtac2NtRkZTbXROVm5CSldsVmtSMkZGTVZoVmJuQlhUV3BXVEZaRVJtRlhSbFp6VjJ4d1YxSllRakpXUmxKSFYyMVdXRlpyYUZOaVdGSlVWRlZhZDFOV1duTmFSRkpyVFd0YVNWVnNhR3RoVmtwR1RsWm9WMkZyTlZSWlZWcHpUbXhHVlZKdGNFNVdia0Y0VmxSS05GRXhXWGROV0ZKb1VtMTRXRlZ0ZUdGV1JscDBUVlprYWsxWFVqRlZNbmhoWVVVd2VGTnVXbGRTYlZFd1ZYcEtWMk15U2tsU2JGWnBWMFpLZGxadE1UQmtNV1JIVmxoc2JGSlViRmhVVjNSaFpWWnJkMWRzVGxkaVZscDVWako0YjFZeVNrZGpSV2hhVFc1b00xVXdaRXRUUjBwSFZHeGtVMkpJUW1GV2JYQkhXVlpaZUdKR1pGWlhSM2hWV1ZSS1UxZFdXWGRhUnpsWVZtMTRlVll5Tld0WGJGcDBaVVpzWVZKV1dqTlpWRUY0VmpGYWNWWnRSbGRXYkhCdlYxWlNRbVZHV25SVWExWlNZa1phY0ZWdE5VTldWbHAwWTBWa1dsWnNjRmhXTWpWTFZtMUtTRlZyT1ZwaVdGSk1WV3hhYTFkWFRrWmFSbEpPVmxkM01GWlVTVEZVTWtaSFUxaGtXR0pHU2xoVVZWcGhWRVphY2xkdFJsTk5WbkI2VjJ0YWQxWXdNVlpqUm14WFRXNVNhRmw2U2tkak1VNXpWbTFzVTJKWGFGZFdiWEJQVlRKR1IxZFlhRmhpVlZwVlZXcEdTMU5zV2tobFIzUldUVVJHU2xWWGNHRlhSbHBHVTI1S1ZtRnJXbWhXYWtaclYxZE9TR0ZHVGs1aVYyaFlWakZrTkdJeVNYbFdiR1JxVW0xb1QxWnNaRk5WUm14eVZtNWtiR0pHYkRWYVZXUXdWbGRLUm1KRVdsaFdSVFY2Vm1wS1MxSXlUa2xTYlVaWFZteFdORlpVUW1GVE1rMTVVbXRrVldKWGVGUlVWekZ2Wkd4YWMxVnJUbGROVlRFMFdXdGFhMVp0U2tkalIyaFdZa1pLV0ZaRVJtRmtSMVpHWkVaa2FWSnNiM2RXUjNoclRVWmtSMU51VG1wVFIzaFdXV3RhUzFOR1dYbGpNMmhVVW14YU1WWXllR3RXTVVwV1YxUkNWMkpZUWt4V1JFWkxWakZ3U1ZSdGFGTmlWa3BRVmtaYVYyUXhWbk5YYms1WVlsaENjMVZ0ZUZkT1JscElaRWQwVjFZd2NIcFdNbmhyVjIxRmVGZHJlRmROVm5CWVdURmFTMk50VWtobFJrNXBWbXR3WVZZeWVGZFpWbEY1VW01S1RsZEZOVlZaVkVwdldWWnNWVkp1WkdwaVIxSllWakowTUZVd01WWk9WRVpXVmpOb2FGbFdXa3BsUmtwWldrWmtWMDB5YUc5V2JGSkhWMjFXUjFkdVZsUmlSVXBZVkZjeGIxWldaRmhrUjNCUFVqRmFXRll5TlZOVWJFcEdWMnhXVlZadFVsUlVWVnBYWkVVMVZtUkdWazVXTVVwSVYxUkNhMkl4V1hsVGJsWlNZVEpvV0ZsVVJuZFdNWEJXVjI1a1UySldTa2hXVjNocllWWktXRTlVVGxkaVIwNDBWR3RhYzFZeFZuVlViRkpwVWpOb1ZGWnFRbXRPUm1SSFZXeGtXR0p0VW05VmJURTBWbXhXZEdWSFJtbFNiSEI1V1RCYWQxZHNXbGhWYWs1WFZrVndURll3WkVkU01VcHpXa1prVGsxRmNFNVdiWGhUVXpGT2RGWnJaR0ZUUmxwVVdXdFZNV05HVlhkV2EzUldVbXh3V1ZSV2FIZFViRnB6WWtSU1YwMXVVblpXUjNoTFVqRmtkRTlXVmxkaVNFRjZWa1phWVZZeFpFaFdhMnhoVW0xb1ZGbHJhRU5UUmxwSVpVZEdWazFYVW5wV01qVlBWakpHYzFOdFJsVldNMEpJVmxWYVZtVkdjRVphUms1T1lURndTbGRYZEdGVU1WSnpWMnhzVW1KRk5WaFpiR2hUWVVaYWNWSnNjR3hXYkVwYVdWVmFWMkZGTVZsUmJFWlhZbFJDTkZscVNrNWxSbHAxVW14V2FWSlVWbGhXUmxwdlVURmtWMk5HV2xoaVdGSldWRmQwZDFOR2JISlZiR1JhVm14d1dWWldhR3RXTWtWNFZtcFNXazF1YUhKWk1WcEhZekZrY2s1WGJHbFNWemsxVm1wR1lWbFdiRmRVYmxKWFlteEtWRmxVU2pSVk1XeHlZVVZPYWxKc2JETlhhMk0xVmtaYWRGVnViRmRXTTFKeVZtMXplRlpyTlZaYVJsWlhZa2hDZVZadGVHdFRNV1JYVm01V1VtSkhVbkJXTUZwTFlVWmFSMWR0UmxwV2F6VkpWbTEwYjFWR1duTlhhemxhVmtWYU0xWXdXbUZTTVdSMFQxWlNUbFl4U2twV1ZFa3hVekpHYzFOWVpGaGlWMmhZV1Zkek1WUXhjRlpYYlVacVlrZFNNVmRyV210VWJHUkdVMnRvVjAxdVVtaFpha1pXWlVaa2NscEdhR2xUUlVwWlZsZHdUMkl4WkVkVmJrcFlZa2RTY1ZsWWNFZFhiRnBJWlVaT2FGSXdWalpWVjNoM1YwWmFjMU5yYUZoV2JWSlVXWHBHYTJNeFduTlZiV3hUVjBWS05sWnRNSGhPUmsxNVZtdGtXRmRIZUU5V01GVXhWbXhzV1dORlpGaGlSbHBaV1ROd1YxWXdNVlpqU0hCV1RXNVNWRmRXV2t0U2JVNUdaRWRHVjFZeFNsRldWekI0VXpGT1NGSnJhR3hTTW1oUFZqQldTbVZzV25GU2JYUlBVbXhzTkZscldtdFpWazVHVGxac1dtRXlVblpXUkVaWFkyeGtkRkp0YkU1V2EzQlpWbXBKTVZReFVuSk5WbWhzVTBkb1dGVnVjRUpOVmxsM1drVjBWMDFYVWpGWmExcDNWR3hLZFZGcVNsZE5WbkJvVjFaa1RtVldVbkppUjJ4VFRVWndXVmRYZEdGV2JWWkhWMjVHVTJKVldtRldha1pMVTFaYVdHUkhkRmRXTUZreVZtMTRiMWR0U2tkVGJteFZWbFp3YUZreFdrOWpWa1p6V2tVMVYyRXpRVEZXYTFwaFdWZEplRlpZYkZSaWF6VlZXV3RhWVZkR1VsWmFSa3BPVW14d1JsVnRlR0ZoTURGWVZXcEdXR0V4Y0hKV1IzaGhZekpKZW1GR2FGZFNWWEF5Vmxod1MxTXhUa2RVYmtwb1VteHdjRmx0ZEV0aFJscDBaVWRHV0dKV1JqUldNalZIVlRKRmVsRnVTbFZXYlZKVVdsWmFjMk5zWkhSa1IyaFhZa2hDU1ZacVNqUlNNV1JIVjI1T2FsSXlhRmRhVjNSaFdWWndWbGR1WkZSV2EzQjZWVEl4YzFaR1NsWmpSa1pYWWtkU00xVnFSazVrTURWWlZHMUdWRkpVVmxwWFYzaFhXVmRPYzFWc1pGaGliVkpVVkZaYVIwNUdXWGxOVldSWVVtdHNNMWt3V25OWlZscFhZMGh3VjJKVVJreFZha1pyWTFaU2MxWnNaRk5XYmtJMVZtMHhORmxXVVhoYVJtaFRZVEpTYUZWcVNqUlhSbXhWVTFSV1RrMVdjSHBXVjNRd1ZERkpkMkpFVWxkaVIyaDZWbXRrUzJNeFpITlViSEJwVjBaSmVsWnRjRWRqTVdSSVZXdG9VMkpYYUZSWmExWjNUbXhhY1ZOcVVsVk5WbFkwVmpJMVMxUXhaRWxSYkdoV1ltNUNTRnBIZUdGV1ZrWlpZVVprYVZaVVZraFhWRUpoWVRGWmQwMUliR2hTUlhCWVZGWmFkMk5zVm5GU2JIQnNVbTVDU2xWdGVHOWhWbGw2WVVaYVYxWXphSFpWVkVwS1pVWmtjMkZGTlZSU01taFlWMVpvZDFJeFRrZGlTRXBvVWxoU1dWVnFRbmRXYkZwMFRsVTVXR0pWVmpSWk1GWTBWbFphYzJOSFJtRldiRlkwVm14YVIyTXlSa2RVYldoT1RVVndiMVp0ZUdGaGF6RllVMWhvV0ZkSFVrOVdNRnBoWWpGV2MxVnVUbGRpUjNoNVYydGFUMVpHU25WUmEyUlhUVzVOTVZZd1dscGtNazVHWVVaa1RtRnJXalpXYWtKaFUyMVdXRkpyYUdoU2JWSnZWRlpvUTJWV1draGtSMFpvVFdzMWVWUldXbUZaVmtsM1YyeFdWbUpHU2xoWmFrWmhWMGRXUjFSdGNFNVdhMWt3Vm1wSk1WSXhWWGxTV0hCV1lrWmFXRmxzVWtaTlJuQlhWMjVPVjJKSVFrZFhhMlJ2VlRKS1NHUXpjRmRoYTI4d1YxWmFhMlJHU2xsaFJtaFlVakZLV1ZaR1pIZFNNVkpIVjI1T1dHSlZXbkpWYWtKaFUxWldkR1ZGT1dsU01GWTBXVEJXYzFZd01YVmhSMmhZVm14d2VsWnFSbmRTTVhCSFdrZHNhR1ZzV21GV01WcHZaREZaZVZSclpGaGlhMXBWV1d4U2MxVkdiSEpYYms1UFVtMVNlVlpYZEU5aFJrcFZVbXRhVjJKWVVucFdiVEZMVmxaYWMxVnNaR2hOV0VKNVZsUkNhMVl4U1hoalJXUnFVako0VkZSWE1XNWxWbHAwWkVkMFQxSXdNVFZXVjNSdlZtMUZlR05JU2xaaVJrcDZXVEJhVjJSSFVrbGFSbWhYWWtoQ05WWXhVazlpTWtWM1RWaEtXR0p1UWxkVVZ6VnZWMFpzVmxkcmRGTmhlbFpaVlcxNGQxWXhTbGxSYWtwWFlXdEthRmw2Um1GV01WSjFVMjEwVTJKV1NsbFdSbFp2VVRGTmVGcEdhR3RTTUZwd1ZGZDBZVmRHVlhsbFJtUldUVlp3UjFVeWVHOVhiVXBJWVVaU1drMXVhRmhaTVZwTFkyczVWMVJyTlZkTlZXdzBWbTB3ZUU1R1dYbFNiR1JZVjBoQ2IxVnRlR0ZYUmxaMFpVZEdWMUpzY0RCVVZscHJWakF4V0ZWc2NGcGhNbEYzVmxSQmQyVkdUbk5pUm1oWFRURktlRlpIZUZaa01sWklWR3RrV0dKSGFIQldNRnBMVjBaa1dHVkdaR3ROVjFKWVdXdGFZV0ZHU2xWaVJtaFZWak5TYUZwV1dsTmpNa1pJVW14a1YySkhkekpYVmxadlV6RlplVkp1U2xoaGF6VlhXVmQwWVZWR2NFWlhhM1JxWVhwV1dWbHJXazlXTWtwWlZWUkNWMkpZUWtoWlZFRjRVMFpPV1dGR2FGaFNNbWgzVmxjd2VGVXhXbGRpUm1oc1UwZFNjRlJXV2t0V2JGcElaRVU1V0dKR2NIcFZNbmhoVm1zeGNWWnFUbGRTTTJob1drWmFSMk5zY0VkYVJUVm9Za1p3TlZadGNFTlpWbXhZVkZob1lWTkZXbE5aYkZaaFYwWmFjVkpyY0d4aVIxSllWakl4TUZVeVNsZFNhbFpXVFc1Q2FGWlVTa3RUUmxaeVQxWndhVlpGV2pKV1JtUTBXVmROZUZadVNtdFNiRXBQVm14U1YxTldXbk5aZWtaWFRWWmFNRlV5ZEdGV1IwcElaVVprV2xZelRYaGFSM2h6WTFaS2RGSnRjRmRoTVc5M1ZsY3dlRTFHVW5SU2FscFRWa1ZLV1ZadGVFdFZSbXcyVW14S2JGSnRVbnBXYlRGelZrWktWbU5HYUZoV00yaFVWV3BLVDJNeFZuVlViR2hwWVhwV1dWZFhkR0ZaVjFaWFYydG9UbFo2YkZaWmExcDNWbXhhZEdSSE9WZE5WbkJIV1RCU1QxZEdXbk5qUjJoV1lXdGFjbGw2Um10amF6VlhXa1pPYUUwd1NtRldiWGhxWkRKV1IxWllhRlZoTWxKWVZqQmtVMWRHV25KWGJVWllWbXh3ZUZWV1VrZFdSbHAxVVd0a1YwMXVVWGRXYkdSTFVtMU9SMkZHY0U1U2EzQnZWbTF3UW1WR1dYaFViazVTWWtoQ2MxbFVSbmRUVm1SeVZtMUdWMDFyTlhwWk1GWnJWMGRLV0dGRk9WcGlWRVoyVm14YVdtVkdhM3BoUlRsVFRWVlpNVlpyWkRSaE1rWlhWR3RrVkdKck5WZFphMlJUVmtacmQxZHVUbXBpUm5CV1ZXMHhOR0ZXU1hwaFJtaFhZbGhvVkZWcVJtdGpNV1J6Vm14T2FFMHdTbWhXYlhoaFpESk9jMWR1UmxKWFIyaHhWbTE0ZDAxR2JGWlhibVJYVFd4YWVWWXljM2hXTWtwVlVtcGFWVlpzY0hKV2FrWlhaRlpTYzFwSGFHeGlSbkJSVmpGamQyVkhTWGhWYkdSWVltdGFWVmx0TVZOVk1WSllaVVZrVDFKc2JEVmFSV1F3Vm1zeGNtTkZiRnBXVm5CSVZtcEtTMWRYUmtoaFJtUm9UVmhDYjFkVVJtRlVNbEpHVDFaa1dHSlhlRlJaYlhSS1RXeGFkR1ZIZEU1U01GWTBWakkxVTFaSFNrZGpSVGxYWVRGd1RGWXdXbUZqVmxKelZHMXdhVkp1UWxwV1JscFhUVVpWZVZOcldrOVhTRUpaV1ZSR2QwMHhiRlpXV0doWVZtdGFlVmxyV205aFJURldZMFZzVjJKR1NraFZla3BPWlVaYWRWWnNVbWxTYkhCM1ZtcENhMkl5VVhoWGJsSnNVakJhY2xSV1ZURmxiRmw1VGxaT1ZXSkZjRWRXTW5oaFZsWlplbFZ0YUZkTlJuQlhXbFprVTFJeGNFZFhhelZvVFRCS1NsWXhVa05oTVVsNFYyeGtXRmRJUWxOWmEyUnZWMFpTVmxkdVpHeGlSM1ExV2xWa1IyRnNXbkpYYm5CWFRXcEdlbFpxUmxwbGJHdDZZVVprYUdFeU9UTldiWEJMVlcxV1IxZHVWbFJoZWxaWVZtMDFRMWRzWkZoTlZGSmFWbXhzTkZaWGVHdFhSMHBXVjJ4a1ZtSllhR2hXTVZwM1ZtMUdTRkp0YUU1U1JWbzFWMVJDVjJFeFpITlhiR1JxVTBWd1lWWnNaRk5VUmxaMFRWVTVWRkl3V2toWGExcFBZVlphY2xacVRsZGhhMXBvVm0weFVtVldXbkpoUmxab1RWaENXbGRYZEdGWlYwbDRWV3hhVm1KSFVsbFphMXAzVjFacmQxWnJPVmhpUm5Bd1ZsZDRiMVl4V2paV2JFSllWbXh3VEZWdGVFOWtSVGxYV2tkc1UyRXpRa1pXYTJRMFdWWnNWMXBGYUZWaE1taFVXV3RrVTJOR1duTmhSVTVVWWtkU1dGWnRlR3RVTVVwMFpVWm9WMDFxVmxSV2JURkdaV3hXZEdGR1pHaGhlbFl5Vm14V1lWbFhUWGhhU0ZKclVqTkNjRlZ0ZUhaa01XUlhWbTFHYUUxV2JEUldNalZYVld4a1NHRkdhRnBoTVhCTVZUQmFZV05XU25OVGJYaFRZVE5CZUZaclkzaGpNVkp5VFZoT1ZHSnRVbGhXYWs1dllVWldObEpzV214U2JWSXhWVzE0VTJGV1NsVldiRnBYVW14d2FGZFdXbUZqTVZwellVZDBVMDB4U25aV2JYQkRaREZKZUZWdVRsaGlXRkpaV1d0YWQxZEdXWGxsUlU1WVlrWndXRmt3VmpCWlZrcEdVbXBTVjJKR2NISlpla1ozVWpGU2RHSkdUbWxYUjFFeVZtMHhORlV4VFhkT1ZXUlVZbXhLVjFZd1pHOVdWbXgwWlVWMFZsSnNjREJhVlZZd1YwWktjMk5JYUZaaVdGRjNWakJhWVdSR1ZuTmpSbkJPVW14c00xWnRlR3RUTVZsNFdraE9hRkp0VWs5WmJURnZWMVphY1ZGdGRGTmlWbHBJVmtjMVUxVkdXblJWYmtKV1lsaG9NMWxxUm10amJHUjBVbXhrYVZac2NFbFdha2t4VXpGV1IxZHVTbXBUUlVwWFdXMDFRMlZXY0ZobFIzUllVakZLU0ZkcldtRlViRnB6WTBSYVYyRnJXblpaZWtaaFpFWk9kVk50Y0ZOaVZrcFhWbTE0WVdReVJrZFZiR2hzVW1zMVdGUldaRk5sYkZWNVRWUlNWMDFyY0hsVk1uUXdWakpHY21KRVVsWmhhMXBVV1hwR1QxZFhUa2hoUms1WFltdEtXbFp0TUhoT1IxRjVWRzVPYVZKc1dsUlpXSEJ6WTFaU1YxWnVaRmhpUjFKNVZqSnpOV0ZHV25OalJXaFhUVzVvYUZacVNrdFhWMFpIV2taV1YySklRa2hYYkZaaFpERk9WMU51VGxSaVYzaHZXbGQ0WVZac1duTlpNMmhPVW0xNFYxUldXbXRoUlRCNVZXMW9WbUV4V2t4V01GcFRWbXhXY2xwR1VtbFNiSEJaVjFaV2IyRXhaRWRUYms1cVVsZFNZVmxVUmt0VlJscHpXa1YwVkZKc1dubFpWVnAzWWtkRmVsRnNSbGRXTTBKTVZYcEdTbVZHWkhWVmJXeFRUVzVvZGxaR1ZtOVJNVlpYVjI1R1UySllVazlWYlhoelRrWmFSMkZIZEZWaVIxSkhWR3hqTlZaV1drWmpSbEphVmxad1dGcEZWWGhXTVZKMFkwZHNVMkpyU1RKV01WcFhXVlpSZUZaWWFGaGlhelZZV1ZkNFlXRkdWbk5YYm1SV1VteHdNRnBWVm5kaE1ERnlUbFZrV2sxR2NETldha1poWkZaR2NWZHNaR2hoTWpoM1ZqRmFhMVV4U1hoV2JrNXBVakpvVkZsdGRFdFhWbHBZWlVjNVVrMVdTa2hYYTJoUFdWWktSMU51U2xWV2JGVjRWakZhWVZOSFVraGtSMmhYWVROQ05WWkhlR3BPVm14WFYxaHdhRkpYYUZaWlZFWjNXVlp3VmxwRlpGUldia0pJVmtkek1XRkZNVmRoTTJSWFlsUkNORlJWWkVabFJuQkdZVVpPYVdGNlZuaFdWekI0VGtaa1IySkdWbE5pVlZwV1ZXMTRjMDVXY0ZaWGJYUm9UVlZ3VmxWdGVHOVdNVW8yVWxoa1YxSXphR0ZhVjNoMlpXeHdSMXBHVG1sVFJVcDJWbTEwVTFNeFNuUldiR1JWWW1zMWFGVnRjekZpTVd4eVlVVk9XRlpzY0ZsWk1GVTFZVlV4Vms1VmFGcGhNWEJ5Vm1wR2ExTkdWblZVYkdScFYwZG9iMVpHV21GWlZrNUlWbXRzWVZKc1duQldiR2hDWkRGa1YxWnRSbE5OVjFKSVZqRm9kMVZ0UlhsaFIyaFdZVEZhYUZreWVGWmtNV1IwVW0xd2FWWllRa2xXYlRCNFl6RlZkMDFJYkdoU2JGcFlWRmMxYjJOV2NGWldXR2hUWVhwV1dGZHJXbTloUlRGelUyeHdXRlp0YUROV2FrWlNaVVphZFZKc1RtaE5iRXBSVmxjd2VFNUdXWGhYYmxKUFZsUnNXRmxzVm5kV01XdDNZVWhrV0dGNlJrbFpWVlkwVmpKS1IyTkhSbUZXZWtaSVZUQmtSMUl4V25SaVJrNXBZVEJyZVZadGRHcGxSVFZIVlZoc1ZtRXhjRkZXYlRGdlkwWldkR042UmxWTlZsWXpWbTEwTUZaRk1WZGlSRlpoVWxad1VGWnNWWGhXTWtwRlZXeHdhRTFZUW5sV01WcGhVekZrU0ZKcmFGQldiSEJQVlcxNFYwNUdXblJsUjBaYVZqQXhORll5ZUhOaFJrcFZZa1pTV21KWVVreFZNVnBhWlZkU1IxcEhkRTVoTTBKS1ZsUktNRmxXWkVoU2JrcFlZbFZhWVZaclZuZFdSbkJZWlVkR1ZGSlVSbGRhUlZwVFZqSkZlR05FVWxkaE1sRXdXV3BHV21Rd01VbGhSbEpwWWxob1dWZFhlRk5TYXpGSFkwVm9UbFpyY0hOV2JYaDNaVlprY2xwSVRsWk5SRVpJV1RCYVlWWXhXWHBoUm1oaFVrVndVMXBWV25kU01rWklaVVpPVGxKdVFsZFdhMXBYVlRGSmVWWnVUbWhOTWxKWVdXdGtVMWRHV25GUmJIQk9Za2Q0ZVZac1VsZFdNa3BXVjI1c1YwMXFSblpXYWtGNFZqSk9SVlJzWkdsWFIyZDZWbGQ0WVZZeVRYaFdibEpwVW1zMVdGUlVTazlPUmxweFVtMUdWMDFyYkRWVmJHaHZXVlpLV0dGR1VsZE5SMUV3Vm1wR2MyTnNaSEprUm5CWFlsaG9WMVpVU2pSVU1WcFhVMjVTYTFKRk5WaFVWelZUWTJ4c1ZWSnRSbXBpUjFKNFZWZDRZV0ZXWkVoaFJFcFhZa1pLUTFwVlpFNWxSbEoxVW14T2FWSXhTbHBXVkVKWFV6RktWMXBHWkdGVFNFSnpWVzB4VTFOR1draE9WWFJvVW10d2Vsa3dZelZYYlVWNFkwUk9WMVpXY0doWk1WcEhaRVpLZEdSRk5WZE5NbWhhVmpGa01HSXhVWGxTYTJSVVlrWndVRll3Vm1GV2JGcDBUVlpPVjFKc2NEQmFWV1JIVmtaSmVGZHJaR0ZTVm5BelZtcEdZVkpzWkhGV2JHaFhVbFZ3VlZaV1VrZFhiVlpYVkc1T2FWSnJjRzlVVmxaM1YxWmFXRTFJYUZaTlZrcElXVEJXWVZkSFNraFZia3BYWWxob1RGcFhlSE5XYkdSMFpFZHNVMDFHV1RCWFZFSmhVekZaZDAxV2FHaFNSVFZYV2xkMFlWTXhjRlpYYm1SVFlraENTRmxWWkhOaFZrcDFVV3h3VjAxWFVUQlpha1pXWlVaYVdXRkdXbWxTTW1oUlZtMHhNR1F5VFhoV2JsSnNVMFUxVUZadE5VTlNNV1J5WVVkMFYxWlVSbGhaTUZwaFZteFplbEZzYUZkaVdFNDBXVEZhWVdNeFZuTmpSMmhPVjBWS1VsWnNaSGRUTVZGNFZHdGtWR0pyTldoVmFrcHZZakZTVjJGRlRsVmlSbkI1VjFST2IxUXhTWGhTYWxKV1RXcFdWRlpVU2tabFIwNUpVMnhhYUdGNlZrVldiWFJoVlRGYWRGSnJXbFJpV0ZKUFZtMHhNMDFHV25OYVJFSnJUVlpHTkZZeU5VdFViRnBHVGxaYVYySlVSblpXYTFwclZqRmFXVnBIZUZkaVJtOTNWMVpXWVZsWFJsZFRXR2hVWVd0d1dGWnFUbE5oUm5CRlVtMTBWRkpzU25oV01uaHJZVlprUmxOc1ZsZGlXRkp5Vkd0YVRtVkdaSFZTYkZKWVVqSm9lVlpHWkRCWlZtUkhWMWhzYkZJelVtOVdiWFIzVTBacmQxZHRPVmRpVlhCSlZsZDRRMVpYUlhoalNIQlhZa1p3VUZreWN6VldNVlp6Vkcxc1UySnJSWGhXYWtaaFZqSkZlVk5ZYUZkWFIyaFZXV3RrVTJOV1ZuRlRiVGxZVm14d01Wa3dWbUZVYkVwMFZXeG9WMkpHU2toWlYzTjRWMVpHY21OR1pGTmxhMW95Vm14U1IyRXhTWGhVYmxaWVlrZG9XRlJVU205WFZtUlpZMFZLVGxac2JEUldiVFZYVmxkS1IyTkhPVlZXVmtwWVdWVmFZV1JGTVZWVmJYUm9aV3RhTmxacVNURlVNa1pIVTFod1ZtSkhhRmhaYkdoVFRXeFNXR1ZHWkd0U01WcEhWa2Q0ZDFZeVJYbFBTR3hYVm5wRmQxUnJXbHBsVmtwWllVWmtWMUpXY0ZsWFZtUXdXVlpTUjJORldtRlNXRkpVV1Zod1YxWXhVbk5hU0U1V1RWZFNSMVZzYUhOV01rcFpVV3RvVjFaRldrOWFSRUV4Vm14d1IxZHNhRk5OTW1oWFZtMXdRMkV5U1hsVWJHUlhZbXhLVDFadWNITmpWbEpYVjJ4a1RrMVdjSHBXVjNSclZqQXhWbU5JY0ZwTlJrcElWakp6ZUZJeFpIVlRiR1JUVFRBME1GWnFRbXRXTVVsNVVtdGthbEp0VWxoWmEyUXpaV3haZUZkdFJscFdhekUwVjJ0YWEyRnNTbGRYYkZwYVlUSlNWRmt3V21GamJHUjBVbXhrVjJKV1NsbFdNblJUVlRGYVNGTnNaRmhpUjNoWVdXeG9VMWRHV25GVGEzUlVVakJhU2xWWGVHRmhWa3B5WTBWU1dHSkdXbWhaVkVwUFl6RmtkVlZzVG1sWFJVcFFWbTF3UjFNeFpGZFhiazVhWld0YVZGUldXbUZOUmxWNVpVZEdXRkl3Y0VsYVZWcHJWMjFGZVZWc1RtRldNMmd6Vm1wR2EyTXlUa2hsUm1ST1ZsaENTMVl5ZEZkWlZsRjRWVzVPVkdFeGNGbFpWRW8wVjFaYWNWUnNUbWhTYkhCV1ZXMTRhMVV3TVZsUmEyUllZVEZ3VkZsV1pFWmtNazVIV2taa2FWZEZTbEZYVjNCSFZHMVdTRlJyWkZoaVIyaHdXVmh3VjJWR1pGaGtSemxTVFZVMVNGZHJhRXRaVmtwWVZXMDVWMkpZYUROV2JYaFhZekZXY2xwR1pFNVdXRUpJVm1wS05GVXhXblJTYmtwcVVsZG9hRlZzV25kVlJtdzJVbTEwYW1GNmJGaFpWVnBQVmpGS2MyTkdiRmRpV0doeVZGVmFXbVZXVmxsaFJtUm9UV3hLZUZaWGVHdGlNazE0Vmxoa1lWSnJOVmhXYlhoaFRVWndWbUZIZEZWaVJYQjZXV3RTVjFaV1duTlhia3BYVFVad1RGa3lNVXRTVmxwelkwWmtWMDF0WkRaV2JURjNVVzFXUjFkWWFGVmlhelZUV1d0a1UySXhiRlZSYkhCT1VteHdWbFZYTVVkV1JURnlUVlJXVm1KWVVuSldWekZMVTBkR1IxVnNjR2hOYldoRlZteFdZVmxYVG5OYVNFNWhVakpvVDFWcldtRlRSbHBIVjIxR2FFMXJXbnBWTW5odllVWktWV0pHWkZwV1JWb3pXVlZhY21WR1pIVlViWEJwVmxad1NGWnJaRFJoTVZsNVUydGFhbEp0ZUZoWlYzUjJUVVphUlZOclpGTk5WVFV4VlRJeGMxVXhTbkpqUm14WFVtMVNNMVpxUVhkbFJtUlpZa1UxVjFadVFucFdiVEUwV1ZkV2MxWnNhRTVXVjFKWFZGVlNRMDVXWkhGVWJtUlhUVlp3UjFVeU1XOVhSbHB6WTBoS1YyRnJXbkphUmxwWFpFZE9SMVJ0YkZOWFJVcFhWbTB3ZUUxR1dYaFhibEpXVjBkb1dWbHJXbUZXVmxweVZtMUdhbFpzU2xsWk0zQkhZa1phYzFOdWJGcFdWMDB4Vm1wR1dtUXlUa1ppUm5CWFZtNUNSVlp0Y0V0U2JWWkhXa2hHVldKSVFrOVZiVFZEVmxaYWNWRnNXazVXYkd3MFZsYzFVMkZzU2xWV2JHaGFWa1UxUkZVeWVHRmtSMDVHWkVkNGFHVnNXbHBXVnpFMFdWWlNjMWR1VW14U2F6VmhXVlJLVWsxR2JGWlhiVVpxVFZoQ1NWUXhXbUZWTWtwSVpIcEdXRmRJUWxCWmFrcEhZekZrV1ZwSGNGTlhSVXBZVmtaak1XSXlVbk5pUm1SWVlUTlNXRlp0ZUhkbFZscFlaVWM1YUZKVVJsaFpNR00xVmpKS1dWRnJhRmRTUlZwTFdsVmFVMlJXV25OVWJXeFRUVlZ3TTFadE1YZFVNa2w0VjJ4a1lWTkZOV0ZVVkVwdlZVWldjVkpyZEd4aVJtdzBXVlZvVDJGRk1WWmpSbHBhWVRGd1VGWnNXbUZXTVU1eVZXeFdhVkp1UWxsWGExWnJWakZPUms5V1pGZGhlbFpZV1d4b2FtVldXblJsUjNCT1ZtdFdORll5ZUd0WFIwVjRZMGhHVm1KWWFFeFdiWGh6WXpKR1NFOVdaRk5pUm5BMlZtcEtlazVXWkVkWFdHUllZVEo0WVZsVVJuZFZSbHBJWlVkR1dGWnJXbmxhUlZwcllWWmFSbE5ZY0ZkU2JIQnlWa2N4VjFZeFRuVldiRlpwVW14d2RsWkdXbTlSTWxaSFYyeFdVbUpHY0U5V2FrSmhVMFphZEU1Vk9WcFdhM0I1Vkd4YWMxWnRTbFZXYTFKWFRVWndhRnBGWkU5U2F6bFlZa1pPVGxORlNrbFdhMlEwVlRGRmVHSkdaRmhpUjJoWFZqQmtVMWxXV25SbFNHUm9VbTEzTWxVeWREQlVNa3BHWTBod1dsWldjSFpXYTFwTFZtMU9SazVXWkdsV1JWbDZWbGR3UzFWdFZsZFdia3BoVW14S2NGbFVUa05rTVZwWVRWUlNhMDFyYkRSWmExcFhWVzFLZEZWdVRsWmlXR2d6Vm0xNFYxZEhWa2hTYld4VFlUSjNlbGRVUW05a01WbDRWMWh3Vm1KcmNGaFpWM1IzVTBac05sSnJPV3RXYTFwNlZtMTRhMVJyTVZaaWVrcFhZVEpPTkZSclduTldNVkp5WVVaV2FFMVlRbGRYVjNSaFV6Sk9SMVp1VGxoaVNFSlBWVzE0ZDJWR1ZYbE9WM1JZWWtad2Vsa3dWbTlXTURGMVlVZG9WMUl6YUdoVmFrWlBZekpHUjFkdGJGZFNWbkJXVm0xNFYxbFdXblJWV0doWVlrWmFXRmxyWkc5WFJsSldZVVZPVkdKSFVubFdiVEZIVmtVeFYxTnVjRlpOYm1oeVdWZDRTMUl5VGtkaFJsWlhZa2hDVFZac1ZtRmpNRFZ6VTI1S1lWSXpVbFJaYTFwM1RsWlplV1JIUmxaTmExcFpWVEowWVdGc1NuSmpSbWhhVmpOU1RGa3llRk5qYkdSMVZHeGtUbFpzY0RaWFZsWnJUa1pWZVZOcmJGSmlSVXBZVlcxNGQxWXhVbGRYYlhSWFRXdHdTbFV5ZUd0aFJUQjRVMjVhVjJKVVJYZGFSRVpyVmpKT1IxZHNaR2xTTVVwYVYxZDBZV1F4WkVkWGJsSnFVbXMxV0ZSWGRGZE9SbXQzVm1wU1YwMXJjRWxXVjNRMFZtMUdjbGR0YUZwbGExb3pWVEJrUjFKck5WZFViRTVvVFZkM01sWnRNSGRsUlRGSFlrWmthVkp0VWxsV01HUnZWbFpzZEdSSVpGWldiSEF3VkZaYVQxWXlTa2hsU0d4WVlURndVRlp0YzNoV01VNXpZa1pXYVZKdVFsRldhMUpMVXpGSmVGZHVSbFppUjFKd1ZtdFdSbVZHV25SbFJscHNVakExTUZVeWRGZFdiVXBKVVdzNVZtSlVWa1JVVjNoclYwZFNTRkpzVms1V1dFSTFWa2Q0WVdFeFdraFRhMmhXWW10S1dGUlZaRk5rYkZwSFYyMUdWRkl4V2tsVmJURXdWR3hhV0dSNlFsaFdSVXBZV1ZSR2ExTkdUbk5pUmtwcFVtdHdXVmRYZEdGVE1XUkhWV3hXVTJKVldsaFVWbVJUVFVad1JscEhPVlZpUm5CV1ZtMXdZVll4V1hwaFNGcGFWa1ZhVjFwV1drOWpNVnB6V2tkc1UySklRbHBXTVdRd1dWWmFkRlpyWkZkaVJscFVXV3hvVTJOV1duUmtTR1JPVm0xU2VWWXlNRFZXTURGRlVtdG9XazFHV2pOV01GcGhVbXhPZFZOc1dtaGhNWEI1Vmxkd1IxUXlUWGhhU0ZKcFVtczFWRlpyV21GWFZscHlWMjFHV2xadGVGbFZiWFJyWVZaS2MxZHNWbHBYU0VKNlZteGFWMlJIVGpaU2F6VlhZa2hDV2xkc1ZtdFNNa1pIVjFoa2FsSllRbGRXYm5CWFpXeGFjVkpyZEdwTlZUVjVWa2Q0VjFZeVNrbFJhM2hZWWtaYWNsVnRNVmRrUms1eVYyeENWMkpXU2xwV1Z6RXdaREExVjFkWWFHRlNSa3BZV1Zod1IxZFdXblJrUjNSb1ZtczFSMVl5ZUU5WGJGbDZWV3Q0VjJKR2NIcFpNbmhoWXpGd1JrNVZOVmRpUnprelZtdGFWMVV4U1hoWFdHaFVZbXMxY1ZWdE1WTldiR3h5VjIxR1ZsSnNiRE5YYTFacllXMUtSazVVUmxwTlJuQm9XVlZWZUZkV1JuSmlSbVJvWVRCd2IxZHJVa2RUTWxKSFZXNUtZVkpzU205YVYzaGhWbFphZEUxRVJsSmlWbHBJVmpJMVIxVXlTa1pPVms1VlZqTlNXRlJyV2xabFIwWkpWR3hrVG1FelFqWldWRW8wV1Zaa2MxZFljRlZYUjJoaFZGVmFkMVpHV25STlZXUlRUVlpLTUZsVldrOWhWa3AxVVZSQ1YySkhUak5hVlZwS1pWWktXV0ZHVW1saE0wSlJWbTB3ZUZVeGJGZFhiazVZWWtoQ2NsUldXbmRUVm5CV1YyNWthRTFFUm5sVWJGWjNWMnN4UjJOR2FGZFNNMmhoV2xWYVQyTldUbk5hUlRWWFltdEtOVlpzYUhkVE1WSjBWbXRrVm1Kc1dsaFphMXBoWTBaVmQxWnJkRlpTYlZKWlZGVm9iMVpYU2xkWGEyaFlZVEZ3Y2xZeWMzZGxWMFpIVm14V1YySkdWalJXVjNCSFZXMVdSMXBJVmxWaVYyaHdWV3hrTTJWc1duRlRhbEpvVFZad1dGWXljR0ZWTWtwSFUyeGFWMkV4V21oWlZWcFhZekZrY2s5WGRGTk5WWEJLVjJ0V2EyTXhWWGxXYmxKclVrWndXRlJXWkZKa01WcHhVbXhhYkZKc2NERldSM2h2VjBaSmVtRkdhRmhXTTJoeVdXcEdjMVl5U2tsVGJHaG9UVEZLZWxadE1ERlJNVmw0VjFoc1QxWlViRzlVVmxaM1ZteFdkR1ZIT1ZkTlZXdzJXVlZhVTFkc1duTmpSWGhoVW14d1NGa3llR3RqTVhCSFdrZHNWRkpWY0ZkV2FrWnZaREZKZUZWWWJGVlhSMmhXV1cxek1XRkdWbkZVYTA1WFVtNUNXVlJXVWxOaFJrcDBWV3hvVjFZelVYZFpWbFY0VmpGa2NtRkdjR2hOYldoTlZtMXdTMUl3TlhSVGEyeFRZa1p3Y0ZZd1drdGlNVnB4VW0xR2FFMXJOWHBXTWpWWFdWWktjMk5IT1dGV00xSm9WVEJhYTFkRk5WbGFSazVPVmpGS1NsWlhlRzlpTWtaelZHdGFXR0pHY0ZoWmJGSkhWa1phY2xkc2NHdE5WMUo1V2tWa2QxUnRSWGhqUldoWFVrVmFhRmxVU2t0VFJrNXlXa2R3VTJKWWFGbFhWM1JoVXpGS1IxZHVSbFJpUlhCeVZGVlNSMWRzV2toTlZXUldUV3R3U0Zrd1dtRlhSbGw2Vlc1S1YxWkZjRTlhVldSTFUxWlNjMXBHWkZOV1dFSlJWbTB3ZUU1R2JGZGFSV1JZWWtkb1VGWnNVbk5YUmxaeFVXNWtVMDFYZEROV1YzUnJWakF4VjJKNlNsWmlSMmh5Vm1wR1dtVnNVbkZWYlVaVFZqRktXVlpYTVRSVk1rMTVVbXRvYUZJeWFFOVZNRlpHWlZaYWRHVkhkRTVTYlhoWVZURm9jMVp0UlhoalJUbFhZbFJHZGxrd1dsZGpNVlp6V2taV1RsWnNjRFJXYTJOM1RsWlNjMWR1VG1sU1JrcFlWRmR3UjFOR2JGZFdXR2hYVFZad2VGWnRlR0ZVYlVwelUycEtWMkpZVW5KVmVrWktaVVpTZFZSc1ZtbFRSVXAzVm1wQ1lWTXhVbGRhUmxaU1lsVmFjVlJXV25OT1JsbDVUbFYwYUUxVmNGWldiVFZEVm0xR2NrNVdUbFZXTTJoeVZtcEtSMU5XY0VkVWF6Vm9UVlpzTmxacldtRmlNVTE1VW14a1ZHRXlVbkZWYlRGVFYwWnNkRTVWVGxOTlZrcFhWakkxVDFZd01WbFJhMlJZWVRGd2RsWlVTa3RqYkU1eVpFWmthVlpGU1RCV1YzQkhWbTFXUjFwR2JHaFNiRXB2VkZjMWIxZHNaRmhrUjNSVlRVUldTRlp0TlZOVWJGcDBWV3hzVm1KWWFETmFWbHB6WTJ4a2NtUkhhRmRpVmtwSVZsUktORkV4V1hoVGJrNXFVbTFvV1ZadGVGZE9SbHB4VW0xR2FsWnRVbnBXUnpGdllrZEtSMk5HUmxkaVZFWXpWV3BHYzFZeGNFWmFSMmhPVFd4S1dsZFhlRk5qTVZsNFZXeG9hMU5IVWxsWmExcDNWMVpzTmxSdE9WZE5hM0JJV1RCV2ExZHRSbkpPV0VwWFlrWndhRmw2U2s5VFYwNUhWbTFzV0ZJeWFGWldNVkpMVGtaVmVWVnJhRlZoTVhCUVZtcEtiMVF4V1hkV2EzUnBUVlp3TUZSV1VsTmhSMFkyVW14b1YxWnRhSHBXVkVwR1pWWldjMkpHY0ZkTk1tZDZWbXBDWVdNeVVraFVhbHBUWWtoQ1dGbHJWbmRXTVZwVlUyNWtWazFyVmpSV01qVlRZVEZLUms1V2FGVldNMEpIV2tSR1lWSldUbkprUms1T1ZqRktObFpxU2pSaE1WSjBVMjVTYUZKR2NGaFpiR2hEVTBaV05sRlVSbXRTYXpWNVZqSnpNVll5U2tsUmJFSlhZbFJGTUZwRVJsZFdNV1J6V2tkR1UxSnJjSGxYVjNoaFVqQTFWMVpZYkd0U01GcFlXV3hXZDFJeGEzZFhiVGxYVm14c05sbFZWalJXTVVwWFkwZG9WMkZyV2xoWk1uaFRZekZXY2s1V1RsTmlTRUpoVm1wR1UxRXhXWGxTV0doaFUwWktXRmx0ZEhkWFZteDBaRWhrV0ZKdGVGbGFSVll3WVVaS2MySkVVbGROYm1oUVdWZHplRmRIVWpaVGJGcHBWMGRvZVZkV1dtRlRNVnBYVjI1S2FGSnRhRmhWYkZaM1ZsWmFXV05GWkdoTlZXdzBWMnRvUzFkSFNsbFJiRkphWWtkU2RsbHFSbUZrUlRWWldrWk9UbFpzY0VsV2JHTXhWREZaZUZkcldsaGlSM2hYV1ZkMFMyRkdWWGhYYmtwclRWZFNlbFpIZUdGVWJGcDFVVzFHVjFadFVqTlhWbHBhWkRBeFYyRkdWbWhoZWxadlZtMTRZV1F4WkVkalJWcFlZWHBzV1ZacVFuZFRSbHBJVFZoT1ZrMUVRalZaVlZwelZqQXhXRlZVUWxwaGEzQkxXbFphVTJOc2NFZGhSMnhUVFRKb05GWnNZM2RsUmxWNFZtdGthVk5GY0doVmExWkxWREZTVjFwR1RteFdiSEJaV2xWVk5XRkdTWGRqUldSYVlURktWRlp0YzNoa1ZsWnpZVVprVGxJeFNrbFhWRXA2VFZaYWMxWnVUbUZTYXpWWVdXMTBTMWRzV25SalJVNVhZWHBXV0ZkclZtRlVNVnAwVld4a1dtRXlVbFJXTUZwaFkyeGtkRkpzVGxkaVNFSTBWbFJKTVdFeFZYZE5XRTVUWVd4YVdGWnFUbE5oUmxwV1YyMUdhMUl4V2twVlYzaGhZVlpKZVdGRlZsZGlXRkpvVmxSR2ExSnJOVmRoUjNSVFZrWmFVRlp0TUhoTk1ERlhXa2hPVjJKWVVuSlVWM1JYVFRGU1YyRkZPVmhTTUhCSlZsY3hSMWRzV2taWGJXaGhVak5vZWxacVJtdGphemxYVkdzMVYwMVZiekZXTW5SWFdWWnNWMVZ1VGxSaWF6VndWRlJLTkZkV2JISlhiVVpvVW0xM01sVXllRTlWTWtZMlVteGtWMkpZYUZCWlZscHJVbXhPYzFac1pGTmlSbkF5VmxaamVGVnRWa2RhUm14cFVqTlNWRlJWV25kV1ZscEhXa1JDV2xaVVJraFdiR2h6WWtaS2RGVnRPVmRpV0UxNFZXcEdXbVZYVmtsVWJHaHBWbFpaTVZac1l6RlpWbGw0VjJ4a2FsSkZOVmhVVldSVFZVWlNkR1ZIUm10U01IQkpXV3RhYTFZd01IbFVhbEpYWWxoQ1RGUlZXbHBsVmxaWllVWmthV0V6UWxCV2JYaGhaREZrVjJKSVVteFNNRnBZVkZaYVMxZEdXWGxOVldSWFlrVndlbFl5ZUhOWlZscFlZVWRvV2xaRlJqUlpNakZQVW14d1IyTkdaRmROVlc4eVZtMTRVMU14V1hsVWJrNWhVMFZ3YzFWdE1WTlhSbXh5Vm01a1UxWnRVbmxXVjNSTFlUQXhjMWRyYkZaTmJsSjZWbFJLUzFJeFpIVlJiR1JPVW01Q1RWZHJVa2RaVm1SSVZHdGFWR0Y2VmxoV2ExWmhWMVphY1ZOcVFtbE5Wa3A2VlRKMGExZEhTbFpYYkdoYVlrZG9kbHBYZUZOa1IxWkpWR3hrYVZaV2NFdFdNblJoWVRGWmVWSlliRkJUUjNoWVZtNXdSazFHYkhGU2JVWllVbXR3V2xsVlpIZFZNVXBWVm14c1dGWnNTa2hhUkVaWFVqRmtXVnBHYUdsaVZrcFdWbGR3UTFsV1RrZGFTRXBoVWtaS2IxWnRkSGRYYkZaWFlVYzVWMDFyV25sV01qRnZWMFphZEZWcmRHRldWbkJvVmpGa1MxSXhWblJoUlRWcFZqSm9XRlpxUm10TlJteFhZa1prV0dKSFVsbFpiWFIzVjFac2RFMVdUbGRTYkhBd1ZGWlNVMWRHU25OalJFSmhVbGRSZDFsVldscGtNazVHV2taV2FWSnVRbmxXYlhCSFUyMVdjMVp1U214U2JXaFlXV3RhV2sxR1dsVlJiWFJYVFZWd2VsWXlOVTlYUjBwSVZXNUNWMkpZVWpOVWJGcGhZekZXY21SRk9WTmhNMEYzVm14YWIySXhXa2hUYms1VVlrVktXRmxzYUc5VVJsbDNWMjFHYWxacmNIbGFSV1J6Vkd4WmVGTnFWbGROVmtwUVdXcEdZV05yTVZkaFJscG9UV3hLVjFkWGRHRmtNbEp6WWtaV1UyRXpVbkZVVmxVeFpXeHNWbGR1WkdoU1ZFWllXVEJqTlZkSFJYaGpSMmhZVm14d2FGbDZSbmRUVms1elVXeGthRTB3U2xGV2JUQjNUVlpGZUZwSVRsaGlhM0JoV2xkMFlWZEdVbGRYYms1UFZteFdOVnBWYUU5aFJrcHlZMFpvVjAxdWFIcFdNbmhhWld4V2RXSkdWbGRpU0VJMlYydFdhMVl4U25KUFZtUmhVako0VkZsVVRrSk5WbHB6Vld0d2JGSnJiRFJXVnpWVFZURmtTR0ZJUmxaaVZGWkVWakJhYzFkSFVraFNiWEJwVWpOb1YxWlVTakJoTVdSSFUyNUtUMWRJUWxoWmJGSkhaR3hhU0dNemFHcE5WVFY2VmpKNGEyRldaRWhoU0d4WFlrWktURlZxUmtwbFZsSnlWMjFvVTFaR1dsbFhWbWgzVmpGa2MxZHNhR3hTYXpWWVZGWmtVMWRHYTNkV2JVWllVakJ3UjFSc1dtOVdWbGw2VldwT1ZtRnJXbWhaZWtwSFUxWlNjMXBIYkZOaWEwcEpWakZTUTJJeVVYaFhiazVZVjBoQ2IxVnJWbmRoUmxaeVZtNWtWVkpzV2pCYVZWcHJZV3N4Vms1WWNGaGhNVlY0V1ZaYVMxZFdSbkpPVm1ScFYwZG9iMVpzVWtkU2JWWkhWR3hzYVZKc1NuQlpXSEJYWWpGYVZWRnRSbFJOVmtZMFZqRm9hMVl4V2taWGJrWlZWbXh3TTFSVldsTmpNVnB5VDFaa1RsWnVRWGRXYkdNeFlqRlplRk5ZY0ZaaVJVcFlWbXRXWVZSR2NFWldWRlpYVm14d2VsWnRjekZXTWtwSVpFUk9WMkpZUWtSWlZFWkxaRVphYzFwR1pHbGhlbFoyVmxjd01WRXlUa2RXYmxKc1UwZFNVRmxyV25kV2JGWllUVlZrYUUxRVJsZFViRlp6VmpKS1dWVnVXbHBXUlZwTVdUSnpNVmRGT1ZkalIyeFRUVzFvTlZaclpEQlpWbVIwVm10a2FsSlhlR2hWYlhoTFZERnNXV05GV2s1V2JIQjZWakl3TldGVk1WaGxSbVJWVmxkb2VsbHJXazlTYkU1eldrWldWMVl4U2xWV2JYUmhWMjFXV0ZaclpGVmlSMmhVVkZaV2QxTnNXbGhOU0doclRXdGFXRlV4YUc5V1IwWnpWMnhzVjJKWWFHaFdNRnBUVm14d1JscEdaRTVXVkZaaFZqSjBWazFXV1hoVGJsWlNZa2Q0V0ZadWNFTk9SbHBJWXpOb1YwMVhVbmxXTW5odllWWmFWMk5HV2xkV00yaFVXWHBHV21WSFRrZFhiR2hwVWxSV1dWWkdXbUZrTVZwelYyNVNhMUpyTlZoVVZWSkhUVlpXV0dSR1RsaGlWbHA1VmpKNFExWnRSbkpqUmtKV1lsUkdURlZxUm1Ga1IwcEhXa1UxVG1KWGFGTldiWEJIV1ZaVmVGVllhRk5YUjNoWFdXMXpNV0ZHVm5STlZ6bHFZa1phZWxaWE5VOVdhekZYVTJ4b1YwMXVVbkpXUkVaTFl6Sk9SMkZHY0ZkV01EQjRWbTB4TkZNeVRYbFVhMlJxVW14d1dGUlVTbTlsVmxwMFRVaG9WRTFYVWxoVmJUVlhZV3hLYzJORk9WcGlWRVoyV1dwR1lWZEhWa2hTYkZKT1lYcFdOVlpFUm1GaE1XeFhVMjVTVm1KSGFGaFpWRVozV1Zad1dHVkhSbXBOVjFJd1ZXMHhiMVJ0UlhoWFZFSlhZVEpOZUZaRVJsWmxSbkJHWVVaYWFWSnNjR2hYVjNodllqSkdSMXBHWkZoaWF6VllWbTF6TVdWV1VuTldWRVpYVFd0d1dsbFZXbk5XTWtaeVlUTm9WMUpGV25KVmFrWlBWMWRHUjFSdGFHbFNia0poVmpGYVUxSXlVWGhhUldSWVlrWmFWRmxyYUVOak1WcHhVVzFHVkZKc1ZqVmFWV1F3WVVaYWNtTkliRnBOUmxwNlZtcEtTMU5HVmxWUmJHUlRaV3RhVkZkc1dtRlVNazV6V2toT1dHSlhlRlJXTUZaTFYyeGFjbGR0ZEU5U2F6RTBWbGQwYTFkSFNraGhTRTVXWW01Q2Vsa3dXbE5XTVZwVlVtMTRhVkp0ZHpGWGExWmhZVEZhY2sxWVNsaFdSWEJoV1ZSR2QyUnNXbkZUYTNSVVVteGFWbFZYZUdGaFZtUklZVVpXVjJKVVJUQmFSRVpQVTBaV2NtRkhhRk5OYldoNlYxWlNSMlJyTVVkWFdHaGhVa1ZLY0ZSV1ZuTk9SbVJ5WVVVNVdGSXdWalJaTUdoSFZtMUtWVkp1V2xkaVdHaG9XWHBHYTJNeVRrWk9WazVwWVRCd1NWWnRjRXBOVjBWNFYydGtWRmRIYUZsWlZFbzBZVVpXYzFkdVpGWlNiSEJKVkZaV01GZEdTblZSYTFwWFlsaG9jbFpIZUZwbFZtOTZZMFprYUUxVmNFbFdiVEI0VmpGWmVGUnVWbFZpVjJoVVdXeGFTMlF4V2xoalJYUnBUVlphV0ZZeU5WTmhiRXBaVlc1Q1ZWWXpUWGhWTUZwYVpWVTFWbHBHV2s1aE0wSktWbXhqTVZNeFpIUlNXR2hxVWtVMVYxUldXbmRsVm5CWVRWVTVVMDFZUWtoWk1GcHJWR3hPUmxOcmJGZGhNbEV3VjFaa1NtVkdaSFZVYkdob1lraENWVmRYZUd0aU1XUkhZa1pXVTJKdFVsWlZiWGgzWld4a2NsWnFRbFpOUkVaWVdUQm9kMWRIUlhsVmJscFhVak5vVEZWcVJtdFdWa3B6V2tkc1UwMXRaRFpXYkZwVFVqRldkRlpzWkZWaWJGcFhXV3RhWVdJeFVsaE5WemxzVm14d1dWa3dWazlYYkZwMFZXdG9WMVl6YUhKWFZscExVakZPZFZOc1pHbFhSMmcyVmtkMFlWbFdaRWhWYTFaU1lsZG9XRlpyVm1GT1ZtUlZVV3hrYVUxWFVucFdNblJoVkRGa1NWRnRSbGRoTVZwb1ZYcEdkMVpzY0VaUFZsSlhZVEZ3TmxkVVFtdGpNVlY1VWxod1VsWkZjRmhVVm1SU1RVWmtWMXBGTld4U2JWSmFXV3RhVDJGRk1WbFJiR1JZVmpOb1dGZFdaRTlTTVdSMVZHMUdVMUpVVmxCV2JURTBaREZPVjJOR1dscGxiRnBZVm14U1IyVldXWGxrUnpsWFRVUkdNVlZYTVc5V01rWnlZMFY0V2sxdVRYaFdha1poWXpGYWMxcEdaR2xTYkd0M1ZtcEtORmxXYkZkV1dHeFdZVEpvVjFsVVJuZFZWbHB4Vkd0T1YxSnRlRlpWYlRWclYwZEtSMkpFVm1GU1ZuQnlXVlJCZUZZeFpIVmlSbFpYWWtad2IxWnFRbXRUTWxKSVVtdGtZVkpzV2xoWmEyaERZakZhY1ZGdFJscFdhM0JZVmtjMVMyRnNTWHBoUmxKVlZsWktXRlV4V210V01WcDBVbXhrVG1FeGNGcFdWM2h2WkRGV2RGSlljR2hTYldoWVdWZHpNVkpHV2taWGJFNXFZa2hDU0ZaSGVFOVViRnB5WTBSYVYyRnJiekJaVkVaYVpVWk9jMXBIY0ZSU00yaGFWbTF3VDFVeFdYaFZiR1JZWWxoU1ZGUldXbmRsYkdSeVdrVmtWazFFUWpSVk1qVmhWakZhTmxGcVVsZFdSVnBMV2xWYVYyTXhjRWRqUjNob1RWaENZVll4WkRSV01XeFlWbXhrYVZKc1dsWlpiRkp6VjFac2MxZHRSbXhXYlhRelZtMHdOVll3TVVWU2EyaFhZa2RvZGxacVFYaFRSbFp6WVVaYWFWZEZOREJXYlhCSFZESk9jazVXWkZWaVIyaFVWbXhvUTFWR1duUk5TR2hyVFZVMU1GWnRkRzlXVm1SSVlVWlNWMDFIVVRCV2JGcHpWbFpPZEU5V1pGZGlXR2hYVmxSS2QxVXhXWGxUYTJoc1UwaENZVlpzWkU1TlZscHlWbGhvVjAxWFVqRlpWVnBoWVZaa1IxSnFUbGRoTWs0MFZYcEdUMU5HV25KV2JFcHBVbXh3ZDFaWE1ERlJNVkpYVjFob1dHSkdjSE5WYlRGVFYwWldkRTVWWkZaaVZYQktWVmN3TlZaV1dqWlNibHBWWWxob1lWcFZXbXRrUmtweldrVTFWMDFWY0VsV2ExSkhXVmRKZUZWWWFGaGlhelZWV1d0a2IxZEdiSEpYYTNSWVVteGFlVll5ZUhkaVJsbDNUbFZrV0dFeGNHaFdSekZIVG14YWNWWnNaRk5TVm5CdlYxZHdSMkV4VGtkVWJrcGhVbXhLY0ZWcVNtOWhSbHAwWkVaa1ZFMUVRalJaTUZaaFYwZEtWbGRzYUZkaVdGSm9WRlZhVjJSSFZraFNiRlpwVW01QmVGWldaRFJqTVZsNVUyeFdVMWRIVWxoV2ExWmhWMFpzTmxKdGRHcGlWVnBKV2xWYVQxZEdTbkpqUm14WFlsUkZkMVpxUms1a01ERkpZVWR3VTFZeWFIcFdWRUpyVlRGYVIySklUbGRpVlZwVlZXMTRkMU5XVWxkVmEwNVhWakJ3UjFrd1ZuTlpWbHBYVTJ4Q1YyRnJXa3hWYlhoUFpGWmtjMkZHWkdsVFJVcFNWakowVjFsV1RYbFVXR2hoVTBVMVZsbHNaRFJqUmxsM1drYzVWMDFXY0RCVVZsSlRWMnhhYzJORVFsZGlXRkp5VmpCa1MxSXlUa2RpUm5CcFVtdHdXVmRVU2pSVk1XUklWV3RzWVZKc1NsUlphMXAyWkRGa2MxWnRPVlZOVm5CWlZUSjBZV0ZXU2tkWGJVWlhZa1p3TTFaRldtRmpWazV5WkVaT1RsWlVWalZYVmxaaFlURlpkMDFJYkdoU2EwcFpXVlJHUzFSR1ZqWlNhM1JxVFZad01WWkhlRk5oVmtsNFUyeENXRll6VWxoYVJFWlRWakZrZFZSc1dtaE5SRloyVmtaYVlWWXdOVmRYYkdoUFZsUnNiMVp0ZEhkTlJscFlUVmM1VjJKVlZqUlpNRlkwVjJzeFIyTkdhRnBsYTFvelZXeGFWMk14Vm5OVWJXeFVVbFZ3YUZadGRHdE9SMGw0VlZoc1UyRXhjRTlXYlRGVFkwWldjbGRyZEZoU2JYaDVWakowTUZaV1NuTmpSbXhhWldzMWRsbFVSa3BsUm1SeVdrWmtVMDB5YURKWFZsWnJVbTFSZVZSclZsaGlSMUpZVkZSR1MySXhXbGhqUldSb1RWVnNOVlpIZEdGWFIwcFpVV3hTV2xaRk5VUldWVnBoVjBkV1NGSnRkRTVTUlZwWlZtcEdiMk15UlhoVGJsSldZbXRLVmxadGVGZE9SbEpWVW14T2FrMVhVakJWYlhoaFZUSktTRTlJYkZkaVZFRjRWVlJHWVZZeFpIRlhiRTVwVW10d1dGZHNaREJaVm1SSFYyNU9XR0V5VW5GWmEyaERVMVpzY2xwSVRsWk5WbkJJVmpKNGMxWXlTbGxWYmtwVlZsWndUMXBWWkV0U01XUnlUbFprVjAxdGFEWldiR1EwV1Zac1YxZFlhRmhpYkVwUFZtMXpNV05XYkhKWGJHUlBWbTVDVjFadE1VZGhSVEZGVW14a1ZXSkdjRE5XTW5oaFZqSk9SVlJzWkZObGExcEpWMVJLTkZsV1pGZGpSV1JvVW0xb1ZWVnNWbmRVYkZweldraGtVMDFyVmpSVk1XaHZWbTFLY2s1WVFsWmlWRVpVV1RCYVdtUXhaSEprUm1ocFVtNUNXbGRzVm1wT1ZsWnlUVlZXVjJKdVFsbFpWRVozWkd4c1dHVkZkRmRXTUhCSVZrZDRWMVl3TUhoVFdIQlhWa1ZhYUZadE1WZFdhelZYVjJ4V2FWWXlhRlZYVmxKUFVURlplRnBHYUd0U01GcGhWbTE0ZDFkR1dYbE9WVGxYVWpCd01WVlhlR3RaVmxsNlZXMW9XbFpXY0doYVJXUlhVMGRTUjFwR1pHbFRSVWt5Vm0xNGEwNUhSWGxTYkdSVllURndWVmxVVGtOWFJteHpZVWM1YW1KR1NubFdNblIzWWtaS2MxZHViRmhoTVhCeVdWVmtTMU5XUm5OaVJtaFhaV3RWZDFZeFdtRmhNVmw1VTJ0c1ZHSlZXbFJhVnpFMFYxWmFXRTFJYUU5U2JWSllWbGQ0YTFZeVNuUlZia0pXWWxob00xcFhlRnBsVjA1R1ZHeHdWMkpJUWxsV2FrWlRVVEZaZUZkWWNGVmhiRXBvVlcxNGQxZEdhM2xqTTJoWFRWZFNlVlJzV210aFZrNUdVMnhPVjJKWWFHaFpWRUV4VTBaV2RWVnNXbGhTTTJoV1YxWlNSMlF4V1hoaVNFcFhZbTFTV1ZWdGVFdFhWbkJXVm1wQ1YxWnJjSHBaTUZwdlZqRlplbFZzUWxkaE1WWTBXVEp6ZUZaV1ZuTmpSVFZUWW10S2RsWnFSbUZaVmsxNFYyeG9WR0V5ZUZOWmExcDNZakZzVlZGc1pFOVNiSEJXVlRKd1UxZHNXbk5pUkZKWFlsUldWRlpVU2t0U2F6VlhWV3hXVjFadVFYcFdha0poV1Zaa1JrMVZiR0ZTVkZaWVdXdG9RMU5XV25GVGFsSmFWbXhHTkZZeWVHRlVNVnAwWlVkR1YyRnJOVlJXUlZwM1YwZFdSMXBIY0dsU01VbzFWakowWVdJeFZYbFRia3BVWVRKb1dWWnJWa3RoUmxZMlVteE9hazFWTlhwWGEyUjNWVEZLVjJOR2JGZGlXRkpZVjFaYWExSXlTa2xTYkU1cFVtNUNlbFp0TVRSVE1sWlhZa1phV0dKRk5XOVdiWFJ6VGxac1ZsZHVUbGROYTFwNVZUSXhiMWRHV25SVmJFSlhZV3RhV0ZsNlNrZFNhemxYV2tkNGFWZEhaekJXYlhSaFdWZEZlRlpZYkZkaWF6VndWVzE0ZDFkR2JGVlViRTVwVFZad2VsWlhkR3RWTWtwSFYycENZVlpYVWtoV2FrcExVakpPUlZGc2NGZFdiSEJWVm0wd2VGSnRWbGRXYmtwb1VtMVNjRll3Wkc5VVZtUnlWbXhhVGxac2JEUldiVFZQV1ZaS2RGVnNhRlppV0dnelZXMTRZV1JIVGtaa1IzUk9WbFpaTVZacldtOWlNVnBJVWxoc1ZtSkdTbUZaVkVwVFpHeHNWbGRzWkdwV2Exb3dWVzE0YjFVeVNrWmpSbVJYVmtWc00xUldXbE5rUms1eVdrZHNVMUpzY0c5V2JYaGhaREZXUjJKR1ZsUmhNMUpVV1Zod1IxWnNXa2hsU0dSb1VsUkdXRmt3V2xkV01rcElWVlJDVjAxcVJsaFdha1poWkZaT2RHUkdUbWxUUlVwYVZteGtORll5VVhoVWJHUmhVbTFvVDFacldrdFdiRkpYVjI1a2JHSkdjRmxVYkZZd1ZqRkpkMk5HWkZkTmJrMHhWbTB4UjJOck5WbFhiRnBwVjBkb2IxWnRjRWRoTWxKSVZXdG9hRkpVVmxoVVZFcHZWMVphY2xkdFJtbE5Wa1kwVjJ0V2ExbFdTbGhoUm1SYVlUSlJNRlpxUm5OV1ZrcDBVbTE0VjJKclNsaFdha2t4WVRGYVIxTnNWbE5pUjFKWldWUkdkMlJzV25GVGExcHNVakJzTmxkcldtdGhSMFY1WkhwQ1dGWXpRa2haVkVaS1pVWlNkVlJzYUdsWFJVcFdWbGN4TUdReFpGZFhhMlJZWWxWYWNsUlhjekZsYkZsNVpVWmtWMUl3VmpSWk1HaFBWakpLV1dGRmVGVldiSEJvVmpCa1YxTkhVa2hoUm1ST1UwVkpNVlpzVWtwTlYwbDRXa1ZvVkdFeVVuRlZNRlozV1ZaYWNsWnVaRlpOV0VKWFZqSjBNRmRHV1hkalJXeGFZVEZ3VUZacVJtdFNiRTUxVjJ4a2FFMVlRbGxYVmxKQ1RWWkplRlJ1VG1GU2JWSndWV3BHUzJJeFdsaGpSVGxXVFZad1dGbHJhRXRXTWtwSVZXczVWVlpzY0doVVZWcFRWbXhXY2xwR1pFNVdXRUkyVjFSQ1lXRXhXbGhUYTJSWVlrVktXRlJWWkZOVFJtdDVaVVU1YTFZd05VaFdNbk14VlRKS2NsTnNTbGROYmxKb1dWUkdUbVZHVW5KYVJsSnBZWHBXYjFaWGVGTldNVnBIWWtoU2ExSldjSE5WYlhoM1pXeFplV1ZGT1ZkU1ZFWjVWbTF3VjFZeFduUmhTSEJYVmtWYWNsVXdaRWRUVmtwelYyMXNWMUpXYjNsV2JYQkhXVlpzV0ZSc1pGVmlhelZXV1d4a2IxWkdiSEpYYkhCc1lrWndlRlV4YUc5Vk1ERlhVMjV3VmsxcVZsUlpWRVpMVW1zMVYyRkdWbGRpU0VKTlZtcENZV014V1hoalJWcHJVbTFTY0Zac2FFTlNNVnAwVFZSU1YwMVdTbnBXTVdoclZHeGFSMU5zYkZkaVdHZ3pXVlZhVm1WVk1WZGFSazVPVjBWS1MxWnNaSHBOVmxsNVUyNUtWR0pGU2xoV2FrNURVMFpXTmxKck9WZE5XRUpLVmtkNGQxUnJNWFJoUm1SWVZqTm9hRmRXWkZkak1rVjZXa1prYVdGNlZscFdWM0JEWkRGa2MxWnNhRTlXVlRWWVZGZDBkMWRzV2xoTlZ6bFhWbXhzTmxsVldtOVdWMHBaWVVWNFdtVnJXbFJhUldSVFUwZEtSMVJzWkZOV2JHdDVWbTF3UjJFd01VZFhXR2hYVjBkb1dGbHRjekZYVmxsM1drUlNWMDFYZUZaV1IzaFBWakF4VjFOc1pGZE5ha1pJVm14YVMyUkhWa2xoUmxwcFZrWmFlVlpzVWt0VE1VNVhVbTVLYVZKc1duQlZha1pMVTFaYWNscEVVbHBXYkhBd1ZrZDBhMWRIU2toVmJHaGFZVEpvUkZwVldtRlNNV1IwVW14V2FWWnNjRmxXYlRFMFl6SkdWMU51U2xSaVIyaG9WbXBPYjJGR1duUmxSMFpyVWpGYVNGWXljekZXTWtWNFYxUkNWMDF1VW5aVmFrWmhVMFpPY2xkck9WZGlSbkJaVjFkNGIxUnRWa2RqUmxwWVlsVmFjbFZxUm1GU01WcElaVWhrVjAxV2NFZFdNbkJUVjBaWmVsVnVXbGRoYTFwb1dUSnplRll4Y0VkaFIyeFRWbGhDV1ZadE1YZFVNa2wzVFZoT2FsSldXbFZaVkU1VFZrWnNjbGR0Um14aVJsWTFXbFZrTUZaWFNsWmpSV1JhVFVaV05GWnFTa3RTTVU1eVZXeGthR0V4Y0ZCWGJGcGhWREZrV0ZKcmFHcFNhelZZV1cxMFMyUnNXbk5aZWtaclRWWnNOVlZ0ZEd0V2JVcElWV3hvV2xaRk5WUldNRnBoWkVkV1NGSnNhRmRpUlhBMlYxWldhMDFIUmtkWGJrcHFVa1ZLV0ZacVRsTmpiRnB6VjIxR2FrMVZOWGxaVlZwclZHeEtkVkZ0T1ZoaE1WcHlWV3BHUzJSR1duSmFSM0JUVFc1b1dWWlhlR0ZrTVZwelYxaG9hRk5IVWxWVVZscExUVVphZEU1V1RsWk5hMVkxVmxjMVExWnRTbGxoUkU1WFRVWndNMVl3VlhoV1ZsWnlUbFprYVZORlNsaFdiR040VGtkRmVGZHNXazVXYkhCWldXMDFRMWxXYkZoamVrWnJZa2Q0V1ZwVlZqQmhNVWw0VjJ0c1ZVMVdjR2haVldSSFRteGFjbFpzYUZkaVJuQnZWbXBKZUZWdFZrZGFTRlpVWWxoQ1ZGUlVSa3RWUmxwMFpVWk9WMDFYVWtoV01qVlRWR3hLUmxkc1dsVldNMUpZVkd0YVdtVlZOVmRhUmxwcFZsWlpNVmRzVm1GaU1XUjBVMnRvYUZKV1NsaFpWRVozWVVaYWMxZHJkR3RTTVVwSVZrY3hjMVl4V2tkWGEyaFhZbFJDTkZSclpGSmxWa3B5WVVaT2FHSklRbGxYVmxKUFlqRmtSMVp1Vm1wU1ZuQnlWRlphZDFKc1ZYbGplbFpXVFVSR1Yxa3dhSGRYYkZwWVZXdG9WMVpGV25KVmJYaFBZekZXYzFwR1RtbFNia0phVm1wR1lXRXhWWGhYV0doWVlrZDRiMVZ0TVZOaU1YQllUVlJTVjFKdFVsbGFSV1IzVkRGYVZWWnJhRnBXUlRWeVdWVmFTMk5yTlZkYVJscHBWa1ZhVlZaVVJtRmtNVnB6VjI1R1VtSkhVbTlhVjNSaFUyeGFjMXBFVWxKTlYxSXdWVEo0YzJGR1RrbFJiR2hhVmpOU2FGcFhlRk5rUjFaR1drZDBVMkV6UWpWV1IzaHJZakZTZEZOdVVsVmhiRnBZV1d4U1JtUXhaRmRhUlhCc1VtMVNXbGxyV2s5WFJrbDRVMnhDVjJGclNsaGFSRVpyVmpKS1NWVnJPVmRXVkZab1ZtMHhOR013TUhoYVNFcFdZa1UxYjFSWGRIZFRiRlpZWkVoT1YxWnNjSHBXYkZKSFZqRktSbGR0YUZkaVJuQm9XWHBLUzFJeFduUmlSazVPVmxoQ1MxWnRNWGRSTVd4WFZGaHNWV0pzU2xaWlZFbzBZMVpXZEUxWE9WaFNia0paV2tWV2ExUXhTbk5qU0doV1RWZG9kbFpyWkV0V01VcHhWbXhhVGxZeVozcFhWbFpoVXpKU1IxWnVWbEppUm5Cd1ZqQmFTbVZzV25SbFIwWmFWakZLUjFSV1dsZFZiVXBaVldzNVYySllhRE5VYlhoaFkxWk9jVlZ0YkU1aE1XOTNWbTB3TVZReFpFaFRhMlJVWWtad1dGbHNhRzlXTVhCV1YyMUdhbFpyY0RGWGExcHJZVlpLZFZGWVpGZFdla1V3VmxSR1UyUkdUbkphUjNCVFltdEtXbGRXVWtkWlYxSnpZa1pXVTJKVldsaFpXSEJIVjJ4YVdHVkhSbWhTTUZZMlZWZDRkMWRHV25SVldHUldaV3R3V0ZsNlJtRmtWazV6WVVkb1RtSkZjR0ZXYkdOM1RWWkZlRk5ZYUdoTk1sSlpXVlJPVTFac2JISldibVJZVW0xME0xWlhkR3RXTURGWFkwVmtWMDF1YUhaV2FrWkxVbXhrY21GR2NHeGhNMEpNVjJ4a05HUXhUa2hUYTJSVllrZFNiMVJVUWt0V2JGcHhVbTF3YkZKVVJraFdSbWh6VlRKRmVWVnVRbFppVkVaVVZqQmFjMVpXVG5OVWJYQnBVbTVCZDFkc1ZtdFNNVmw1VTJ0a1YyRnNXbFpXYkZwTFYwWnNWMWRyZEdwTmEzQkdWa2Q0ZDJGRk1WWmpSbXhYWWxob2FGZFdaRk5TTVZwelZteEthVkp1UW5wWFZsSlBVVEZrVjFkdVVrNVdSa3BXVkZkNFMxZEdhM2RXYlhSb1lrVnNOVnBWV205V1ZscEdZMGhhVm1KWWFHaFpNbmhyWXpGU2MxUnJOV2hOVm13MlZtdGtOR0l4VVhoWGEyaFVZbXMxVlZsclpGTlpWbXhWVW0xR1ZWSnRlRmRXTW5oUFYwWkpkMDVWY0ZkU2VrVjNWbXBLUzFJeFpGVlJiR1JwVmtWWk1sWkhlR0ZXTWxKSFZHNUthRkpyU2xoVmJGSlhZVVprVjFWclpGcFdiSEJJVmpKNGIySkdTblZSYms1WFlsaG9hRnBXV25kU2JHUjBVbXhrVGxaWVFsaFhWRUpYWXpGa1IxZHFXbE5XUlVwWVZXdFdZV0ZHYkRaU2JHUnJWbXMxZWxaWE1YTldNVnAxVVd4R1YySkhVak5XUkVwS1pVWk9kVlJzYUdsU01VcGFWMWQ0YjFVeVNYaFZiR2hyVWpCYWMxbHJXbGRPUm14V1drUkNXRkpyY0RCV1YzUnpWakZhTmxKcmFGZGhhM0JNVldwR1lWZFhSa2RYYkdSVFZtNUNWVll5ZUZkWlZteFlWV3hrVm1Kck5WZFphMlJUWTBaV2MyRkZTazVTYkhCNlZqSXhkMkpHU1hoU2FsWldZbGhTY2xZd1dtdFRSMVpJWVVaYWFFMVlRWHBXYWtKaFl6RmtTRlJxV2xOaGVsWlBWbTE0ZDFZeFdsaE5SRVpvVFZaV05WVXllR3RXUjBWNVlVWm9WMkZyTlhaV1JWcGFaREZrY21SR2FGZGhNWEExVjJ4V1lXRXhXWGxUYTFwcVVsUkdXRmxyV2t0VVJsWnhVMnMxYkZKdFVqRldSM2hyWVZaS2NtTklaRmRpV0ZKeVZHdGtWMk14WkhWVmJYQlRWbFJXZUZaR1ZsTldNV1JIVjJ4b2JGSXpVbUZXYlhSM1UwWlZlV1ZJVGxkTmEzQmFWbGR3VDFsV1dYcGhSMFpoVm0xU1VGVXdXa3RqTWtaSFZHczFWRkpWY0V4V2FrWmhWakZaZDAxVlpHRlNWMmhVV1cxMGQxZFdiRlZVYlRsWFRWWktWMVl5Tld0V1ZrcDBaRVJTVjAxdVVuSlpWM040WTJzMVZtRkdhR2hOYkVvMlYxWmFZVmR0VmxoU2ExcHBVbTFTY0ZZd1ZrdFVWbHBJWkVkMFUySldXa2xWTW5ScllVWktjazVYT1ZWV2VrWjJWakJhYTFkSFVraGtSMnhPWVhwRk1GWnRNREZUTVZsNVVsaHdWbUpIZUdGWlZFWjNZVVp3V0dWSVRsZGlSM2N5Vm0xNFYyRldXbGxSYTNCWFlrZE5lRmxxUm1GamF6RlpVbXhrYVZKVmNHaFdiWFJYV1ZkR1IxZFlaR0ZTYlZKVVdXdG9RMU5HWkhKWGJYUnBVakJXTkZscVRuTldNREZYWTBaU1ZtRnJXbEJhUlZwWFYxZEdSMkZIYkdsU2JrSmFWakZrTUZZeVVYaFZXR2hwVTBVMVdWbFVUa05qTVZwMFpVaE9UMVp0ZEROV2JYTTFZVWRHTmxKc1pGcE5SbHAyVm0weFMxZFhSa2xYYkdoWFlraENUVlpxUm1GU01sSlhWVzVPWVZJeWVGUlphMk0xVG14YWMxa3phRTlTTUZZMFYydFdiMVpYUlhoalNFWldZa1pLV0ZZd1dsTldNVnAxV2tab1YySldTbGRXVm1ONFVqSkdWazFXWkdwU2JYaFhXV3hTVjFSR1duSmFSVnBzWWtaYWVsZHJXbGRXTVZwMVVWaHdWMkV4V21oV1ZFWnJVMFphY2xkc1FsZGlWa3AzVm0xNFlXUXhUbGRYYmtwYVRUSm9jVlJXV2t0bGJHUnlWbTFHVjFJd2NFaFpNRnB2VmpKS1ZWSnNUbUZTUlZwb1dURmFTMlJIVWtoalJUVllVbFZ3U1ZacVNqQlpWbFY1VW14a1dHRXlhSE5WYlRWRFYwWnNjMVZzWkU1TlZscDRWVzF6TlZVd01YSk9WV2hhVmxkUk1GWnJXa3BsUms1ellVWm9WMDB5YUZsWFdIQkNUVlpaZUdORmJGUmlSMUp3V1d4YVMxZEdaRmRoU0dSVFRWVnNORll4YUhOVU1WcDBWV3hzVm1GclNsaFVhMXBhWlZVMVdGSnNaR2xXYkhBMVZsZDRiMkl4V1hsVGJHeFZWa1ZhV0ZSVldsWmxSbGwzV2tWMFUyRjZWbGxaYTFwcllVVXdkMU5yT1ZkaVZFVXdWMVphVm1WR1NsbGhSbEpZVWpOb1ZsZFhNWHBOVmxwellraEtXR0p0VWxoWmEyUTBWbXhXV0U1WGRHaFNhM0I2VlRKNGExZEhSWGhUYkZKWFlURndhRmw2U2s5U2JVcEhWbTFzVTAxVmNFcFdNVnBYV1Zaa2RGVlliRlZoTWxKWldXdGtVMWRHY0Zoa1JXUlBVbXh3TUZSV1VsTldSVEZ5VGxoc1ZXSkdjR2hXYlRGTFZteGtjMkZIUmxkTk1VcHZWbXhhWVZsWFRsZFNibEpyVW0xU1QxWnNVbGRYVmxwWVRVUkdWazFyVmpSVk1qVkxWREZhVldKR2FGcGlSMmgyV2xaYWQxWXhaSFJTYlhCcFVtNUJkMWRVUW10T1JsVjVVMnRhV0ZaRldsaFphMlJPWlVaYVZWSnRSbFJTYXpVeFZrZDRVMkZXU2xaalJteFlWbTFTTmxSV1pGTmpNWEJIV2tab2FWSlVWbGxXYlRFd1pESldWMXBJU21GU1JVcHZWbTEwYzA1c1dsZGhTR1JYVFVSR01WWlhlRzlYYkZwR1YyeFNXbVZyV2xCV01WcDNVakpHU0dGRk5WZGlhMHAyVm0wd2VFMUdXWGhVYmxKV1YwZG9XRll3WkRSak1WWnpWMjVrYW1KR1NsaFdiVFZyVkd4S2MxTnVjRmROYm1oUVZtcEJlRll5VGtkWGJHUnBWMFpLVlZadGNFSmxSMUpYVW01S1ZtSklRbk5aVkVaM1ZGWmFXR05GWkZSTmJFcFlWbTAxVTJGc1NuSk9WVGxWVm14YU0xZFdXbUZqTVhCRlZXMXNUbFpXY0RWV1JscHZWREZzVjFOdVVtaFRSVnBYV1d0YVMyVnNXbk5YYms1cVlrZDNNbFp0Y3pWVk1rcEhZMFp3V0dKR1dtaFdSRVpoWkVaT2MxZHRjRk5pYTBwWVZtMDFkMVl4U2tkWGJrNVlZa2hDYzFsclZtRmxiR3hXVjJ4a1YwMXJjRXBWVjNoWFZqRmFSbE5zWkdGV1ZuQm9XVEp6TlZZeFpISlBWbVJwVm10d1VWWnNaREJaVmxsM1RsVmtXR0pzU25KVmFrNURWREZhZEUxVVVsaFdiRm93Vkd4YVQxWnJNWEpqUld4YVZsZFNkbFp0YzNoVFJsWnpWV3hrVjFKV2NGVldha0pXWlVaYVYxWnVUbFJoZWxaWVZGWldkazFHV25OWGJYQk9WbXhHTkZac2FHOVdSMHB5WTBac1dsWXpVa3haVlZwaFl6RndSMU5yTlZOaVNFSlhWbFphYjJJeFZYaFhiazVxVWtWYVlWUlZXbmRrYkZweFVtdDBWMkpWTlVaVk1uaHJZVlpKZUZKWVpGaGhNazQwVm1wR1NtVkdWblZXYkZacFZqTm9WVlpHWTNoaU1WcFhWMnRrVm1Fd05WVlVWM1J6VGtaWmVVNVZaRlppVlhCSlZsZDRWMWR0U2tkalJXaFZZVEZ3ZWxreWVHdGtSMUpIWVVkc1YySklRVEpXYlhCS1RWWk5lRmRZYkZSaE1sSlZXVzAxUTJGR1ZuUmxTR1JzWWtkME5GWXljelZoTVVsNFUydG9WMVo2Um5wV1ZFWmhZekpLUlZkc1pHbFNNRFI2VjJ0U1FtVkdXWGhhU0VwaFVtMW9jRlZ0TlVOVlZscDBaVVphVGxadFVsaFphMXB2WVRGS1dWVnVUbHBoTVhCWVZHdGFXbVZYVWtoa1IyaE9WbGQzZWxacVNqQmpNV1J5VFZWa1YxZEhhRmhWYWs1dlZFWldkR1ZIZEdwaGVsWllWMnRhYTFVeFduVlJiSEJYWWxoU1ZGVnFSa3BsVmxKWllrWlNXRk5GU205V1YzQkxUa1phUjFkdVJsUmlWR3haVm0weFUxZFdVbGRoU0dSVllrWnNNMVJzV205V01WbDZZVWhhV21FeGNFeFpla3BQVW1zNVYyTkhhRTVXYmtKYVZtdGtORmxYVFhsVWJrNVlZbXR3Y2xWdE5VTlhSbHB5Vm0xR1ZHSkhVbnBXYlhoclZqQXhWMk5JY0ZkTmFsWlVWbTB4UzJOdFRrZGFSbFpYWld4YU1sWlhjRWRrTVVwWFUyNUthMUl6VWxSV2ExcGhWMnhhV0UxVVVsVk5WbXd6VkZab1UyRkdTbFZXYkdoYVZrVndVMVJWV21Ga1IwNDJVbXhvVTJGNlZYaFdiR1EwVlRGa1IxTlljR2hTZW14WVZtcE9iMlJzVmxWU2JGcHNVbXhhZWxZeWVHdGhWbHBYWTBoc1YySlVSVEJXYWtFeFVqRmtkVlZ0Y0d4aVJuQllWMWQ0VjJReFRsZFZXR2hXWVhwc1dWbHNWbGRPUmxsNVpVWk9WMDFXYkRaWlZXUkhXVlphYzJOR2FGcE5ha1pVVldwR2EyTXhjRWRVYkdSWVVsVndVRlp0Y0VkVk1VbDRZa1pvVmxkSGFGVldNR1EwVmtac1ZWSnVaR3BpUmxwNFZrY3dOV0ZzU25OalNIQllZVEZLVUZaSE1VdFNNazVIVjJ4YWFWWkZSWGhXYlhCQ1pVWmtTRlpyWkdoU2JXaHZWRlphZDAxc1pGZFdiVVpWVFZWd2VWUnNXbXRoVmtwMFZXMDVWVlpzY0ZoVWExcGhZMVpHZEZKc1drNVdia0kyVmpKMGIxWXhiRmRUYmxKV1lrWktZVmxyV2t0bFZsSlhWMjFHVkZJeFdrbFZiWGgzVmpKS1JtTkVXbGRXUld0NFZrUktSMk14VG5OV2JXeFRZbGRvV1ZkV1pIcE5WMUp6VjFoa1dHSlZXbFJXYlhSM1RVWldkR1ZIZEdoV2JIQmFWVmQwYjFkR1duTlhiV2hYVWtWd1NGWnFSbmRTYkdSelZXMXNhVmRIYUZwV2JURjNWREZGZUZWclpGWmlhM0JZVmpCa2IyTldVbGhrU0dSVVlrWndXVlJXVWtOaFZrbDNZMFZvV2sxR2NFUldha3BMVjFaR2NsUnNWbGRpUmxrd1ZsZHdTMVF4U25OWGJrNVhZbGRvYzFsc2FHOVdNVmw0V2tSQ1YyRjZSbGhXUjNSclYwWmtTR1ZJUmxaaGEwcG9WakZhVjJOV1JuVmFSbEpYWWxob1dGWnRNWGRWTVdSelYyNUthbE5JUW1GVVZXUnZUVEZhY1ZGWWFGTk5WbkI0VmxkNGExUnNTWGhUYkd4WFZqTkNURlY2Umt0amF6VlhWMnM1VjJKWGFGVldiWGhxVGxVMVYxZHVVbXBTVjFKdlZGVlNSMU5XVlhoaFJ6bFlVbTFTU1ZwVldsZFhiRnBHVjJwT1dtVnJXbGhaZWtaclkyMVNSMWRyTlZkTk1tUXpWbXRhWVZsV1VYaGFTRTVZWW1zMWNGVnJWVEZYUm14eVYydDBWRkpzY0VaVk1uUXdWa1phY2xkdWJGZE5ibWhvVmtkNFlXTnRUa2RpUm1oWFRURktiMVl4V210Vk1WbDRVMjVXVkdKWGFGUlphMXAzVlVaYWRFMVVRbXROVmtwWVZqSTFSMVpIUm5OVGJHeGFZa1p3YUZwWGVITmpWbEoxV2tkb1UyRXpRWGRYVmxadlVURmFkRk5yWkZSaVIyaFhXV3RhZDJGR1dYZGFSVGxUWWtoQ1NGZHJWVEZoUjFaelYxUkdWMkV4U2toWFZscHpWakZXV1dGR2FHbFNNMmhVVjFkMFlWTXhXbk5YYmtwWFltMVNjbFp0TlVOWFJsbDVaVWhrYVZKc2JETlViRlpyV1ZaS1dGVnFUbGRTZWtaTVZXMHhUMUl5VGtkYVIyaE9Za1ZzTmxadE1YZFNNa1Y1Vkc1S1RsWlhlR2hWYlhoTFlqRlNWMWR1WkdoU2JIQXdWRlpTVTFkc1duSk9WV2hhWVRKb1ZGbHJXa3RXVjBwSFlVWndhRTFZUWsxWGJGcGhWbTFXVmsxV1dtRlNiRnB3Vld4a00wMXNaRmRXYkdSYVZteHNORll5TlU5aGJFNUdZMGRHVjJFeFdtaGFWM2hoWTFaS2RWcEdUbWxXVm5CS1YxWldZVlV4VlhoWGJsWlNZbFZhV0ZSV1pGSmtNV3hWVTJ0d2JGSnJOWGxYYTFwaFlWWktkVkZzYkZoV2VrWTJWRlphWVZJeVNrbFRiR2hwWWxaS2VsWlhNVFJrTVdSWFkwWmFhRkl6VWxoV2FrSjNWakZyZDFadE9WaGlWVnA1Vkd4U1QxWXdNVWhWYTJSaFZsWndjbHBHV2s5ak1rNUlaVWRvVGsxRmNGZFdha293VmpGc1YxVlliRlppUjFKVldXMTRTMk5HVm5OVmJHUlhWbXhhTUZwRmFHdFdWbHB6WTBod1YwMXVhRkJXVjNONFZtMUtSVlpzV2s1aGJGcFJWbTE0YTFNeFNYbFVhMlJZWWtoQ1dGVnNWblpsYkdSWFZtMUdWazFXY0hwWk1GWlhWbTFLUms1V2FGcGhNWEF6VmpGYVdtVlhVa2hrUlRWVFlraENTbFpVU2pCWlZsbDVVbTVLVDFadFVtRlphMXBMVVRGd1ZsZHNjR3hXTURFMldWVmFVMVV5U2tkalJGWllWbXhhY2xWcVJscGxWbHAxVTJ4b2FWSldjRmxXVnpFMFV6RlNSMVpZYkU1V2JWSllWRmR6TVZJeFdYbE5XR1JXVFd0V05sVlhlRU5XTVZsNllVZG9ZVkpGUmpSV2FrWnJZekZhYzFSdGJGTk5WWEJZVm10YVlWWXhiRmhXYms1cFUwVmFWbGxzYUZOaU1WcDBaRWhrV0ZadGVGZFdNakExVjBkS1ZtTkdjRmRTYldoMlZqSnplRll5VGtkVmJHUk9VakZLV1ZaWGNFZGhNazV5VGxab2FWSnJOVmhaYTJRd1RrWmFjVkp0ZEU1U2JHdzBWa1pvYjJGV1NuTmpSVGxYWWtkU2RsbDZSbGRqTVdSMFVteGtUbFp1UVhkV1JscGhWREpHZEZOclpGZGhiRnBvVm14YVlXRkdiRlZSV0doWFlsVTFSbFZYZUZkaFZrcDFVV3hXVjJKWVFraFhWbHBoVmpGa2RWTnNXbWxTTVVwUVYxY3hNRk14U2xkYVJteHFVbGRTVmxSV1ZuTk9SbGw1VGxaa1YySlZjRmxaVlZwVFZsWmFSbGRyZUZkaVJuQm9WV3BHWVdSR1NuTmpSbVJPVmxoQ1dsWnRjRXRPUm14WFdrVm9VMkZzY0hCVmJYTXhWbXhhY1ZSc1RtaFNiRXBYVmpJeFIxZEdTWGhYYTNCWFVqTm9jbFpVUVhoVFZrWlpZVVprVjJKVk1UUldWbEpIV1ZaWmVGcElTbGhpUmtwd1dXMTBTMVl4V25STlZGSnJUV3MxZWxrd1ZtRldNV1JJWVVab1ZWWnRhRVJWYWtaVFl6RmtjazlYYUZkaVZrcEpWbGQ0YjJJeFdYZE5WbVJxVW0xb1lWWnJWbmRUTVhCWFYydDBhazFZUWtoV1YzaHZWa1pLVm1OSVdsZGlSa3BFVjFaa1VtVkdaSE5hUmxwcFVqRktXVmRYZUZkWlZsRjRZa2hLWVZKck5YTlZiWGhoVjFaU2MxWlVWbGRoZWtaWFdUQm9jMVl3TVhWaFNIQlhUVWRTUjFwVldtdGpWbEp6V2taa1RrMUVVWGRXYkdONFRrZEZlVlZzWkZoaWF6VlpXVmh3VjFkR2JISmhSVTVXWWtad2VsWXlNVEJVTVVsNFUycENWMVp0YUhwV2EyUkdaVWRPUjFwR2NHaE5WbTk2VjFkd1IxVXhaRVpOVm1oUVZqTlNUMVp0TlVOVFZsbDVaRWM1YUUxcldubFVWbWhQVmtkS1NHRkhSbHBXUlhCMlZrVmFhMVl4WkhKa1IzUlRZa1p3TmxaclpEUmtNa1pYVTI1V1VtRjZSbGhaVjNSMlRVWmtWMWR0ZEZOaGVsWllXVlZhVDJGV1NYaFRibVJYVmpOb2NsUlVTbGRqTVdSMVVteFNhV0pXU21oV2JUQjRWVEF4UjFkdVVrOVdXRkpaVldwQ1YwNUdWWGxOVldSWFRXdHdTVlpYZUZOV01rVjRZMFprWVZKRlduSmFSbHByWkVkV1IxcEhiR2hOU0VKTFZtMTRhbVZGTlVkaVJtUldZbXMxVlZsclpEUlZNV3h5V2tjNVdGSnRlSGxYYTFwTFZHeEtjMk5FUWxWV2JIQnlWbFJCZUZZeVRrbGpSbWhvVFd4S1NWWnJaSHBsUjFKSVVtdGtWbUpIYUZoWmExWjNVbFprY2xWclpHaE5WV3cwVmpJMVYxWlhTbFpYYkZKVlZrVmFURnBFUm10WFIxSkhWMjE0VTFaR1dqWlhWM1J2VXpGWmVWSlljRlppVkd4WVdWZDBTMWRHVW5SbFIzUnJWakExUjFkcldtdFdNVnBHVjJ4c1YyRnJhM2hYVmxwcll6RmtkVlJzWkdoaVJYQm9Wa1phYTFVeFVrZFdXR2hZWWxWYWNWUlhjekZUVm14V1ZsUkdhRlpyY0ZwVlZ6RkhWakpLV1dGSGFGcFdla1pZVldwR1lWZFhSa2hTYkU1cFZtdHdXbFl4WTNoT1JteFhXa1prYVZORmNGbFpiVEZUVjBaV2RHVkZkRmROVm13MVZHeGtSMVpYU2xaalJXeFhWak5vYUZacVJrdE9iRnB6VVd4d1YxWXhTazFXVnpGNlpVWmFWMVZ1VG1wU01taFBWbTAxUTFac1duUmxSM1JQVW0xU01GWnRlR3RXTWtweVkwaEtWbUpZYUROV01GcFhZekZhZFZwR1VsZGlWa3BhVmtaYVUxVXhXbFpOVm1ScVUwaENXRlp1Y0ZkVVJscHlXa1YwVjJKSFVubFVNVnBoWVVkR05sWnFTbGRXZWtVd1YxWmFXbVZHY0VsVmJYUlRUVzFvVUZkV1VrZGtNRFZ6VjJ4V1UySlViRzlVVm1SVFUxWldkRTVWT1doaVJXd3pWakl4YjFZeVJuSk9WbEpYVWxad2VWcFdaRmRUVm5CSFZXeE9WMUpXY0ZsV01WSkRZVEExUjFkWWJGUmlhM0JWV1ZST1UxZEdiRlZUYXpsUFVteGFlRlZ0TVVkaGJVWTJVbXhrVjAxdWFISldha1pMVmpKT1IyRkdaRk5pU0VKdlZqRmFhMVF4V1hoV2JsWlZZbFZhVkZsVVRrTmxiRnBZWTBWS1RsWnJOVWhaYTFwaFZqRmFSMWRzWkZWV00yaG9WRlZhZDFac1pITmFSbVJPVmxoQmQxWnNaSGRVTVdSMFZtNUtVMkZzU21GYVYzUmhUVEZWZUZkcmRHcE5WbG93V1ZWa2MxVXhaRVpUV0hCWFlsaG9jVnBWVlhoU01rcEhXa2RHVkZKVVZscFhWekUwVXpKT1YxWnVUbGRXUlZwd1ZGWmFkMlZzV2xoa1IzUlhUVVJHV0ZadGNGZFdWbHBYVTJ4b1YwMUhVa3hXYWtaclpGZEtSMVp0YkZOaWEwcEdWbTB4ZDFJeGJGaFVXR3hWWVRKNGNWVnRNVk5VTVZwMFRsVk9XRlp0VW5sV2JYaGhWREZhYzJOSWJGVldiSEJ5Vm10a1IwNXNXblZSYkZwcFVtNUNOVmRzV21GWlYwMTRWbTVLYWxKVVZsaFVWVkpHVFZaYWNsbDZSbFZOVm5CWVYydFdiMVp0U25KVGJHUmFZVEZ3TTFaRldtRldWa3AwVW0xd1YyRjZWalpXYTJRMFZURlNjMWR1VG1wU2JWSllWbTB4VW1ReGJGVlRhMlJZVW1zMWVWWXljelZXTWtwWFUyeHNWMVl6UWxCV1ZFWlRVakZ3UjFwR1pGaFNNbWhXVmxkd1IxbFdTWGhYYmxKc1VqQmFXRlJYZEhkWFJsVjVUbGhPVjAxRVJsaFpNR2hMVm0xV2NsZHRhRmROUm5CUVdUSjRZV014Y0VoaVJrNW9UVEJLWVZadE1IaGtNVTE1VTFob1ZtSkhVbWhWYlRGdlkyeFdjVlJzVGxkaVIzaDZWakl4UjJKSFNrZGlSRlpWWWtad2NsWnFSbHBrTWs1SFkwWmtWMDB5YUZGV2JYaGhXVlpaZUZwSVJsVmlSbHBZVld4YWQyVldXbkZSYkZwc1VtMVNXRlpYTlU5V1IwWTJWbTA1VlZac2NIbGFSRVphWlVad1JWRnNjRmROUkVVd1ZtcEpNVlV4V2toVGEyaG9VbnBzVjFsc2FGTmhSbGw0VjI1T1dGSXhTa3BWTW5NeFZqSktXVm96WkZoaVJscFhWR3hhV21WV1RuSmFSbEpwWWxob1dGWkdaSGRTTVU1SFYydG9iRkpZUW5OWmJGWmhVakZaZVdWSGRGZE5hM0JLVlZjMWMxZEdXbk5UYTJoWFVrVndUMXBWV2s5ak1rcElVbXhPYUdWc1dqTldiVEV3V1Zac1YxZHVUbGhpYkVwelZXMTRkMVF4V25Sa1JtUlBVbTFTZVZsVlZtdFdiVXBXWTBoc1ZXSkdjRlJXYlRGTFYxWldkR0ZHWkU1V2JrSjVWMVJLTkZsWFVsZGpSV2hwVW1zMWNGVXdWa3RYVmxsNFZXdE9WMDFyVmpSV01XaHJWR3hrUjFkdE9WWk5SbG96VmpCYVYyTnNXblZhUm1oVFlrZDNlbFpxU1hoU01rWnlUVmhLYWxKWGFGZFVWM0JIWkd4c1ZsWllhRlJXYTFwNVZGWmFhMkZXU25KalJWWlhUVlp3YUZaSE1WZFdNVnAxVm14V2FWWldjRlpXVjNoVFZqRlplRnBHWkZaaE1IQlBWbTE0YzA1R1dYbE9WazVWWWtad1NGVXllSE5YYlVWNFkwUk9WazFXY0ZSWmVrcEhVMGRTU0dGR1RsZFNWbkJJVm14amQwMVhTWGhhU0ZKVFYwZG9WVmxyWkc5WFJsSldXa1pPVTAxWVFrWlZiVEV3WVd4YWNrNVljRnBXVjFKMldWVlZlRk5XUmxWVGJHUnBVakZHTTFZeFdtRlRiVlpIWTBWYVlWSXpRbFJXYlRWRFpVWmFXRTFVUW10TlZrWTBWbTAxVDFkSFNuUlZhemxYWWxob00xWnRlRmRrUjFaSVpFWmtWMVpGV2xoV2Fra3haREZrZEZKdVNrOVhSWEJoVm0xNGQxUkdXbkZTYXpscVRWWktlbGRyWkc5aFJUQjNVMnhhVjJKSGFETlZha1phWlVaa2MxcEdUbWxoTTBKdlZsZHdTMDVIVGtkV1dHUlhZVE5TVlZWdE1WTlhSbHAwWlVkMFZXSkZjSHBWYlhCVFZqQXhkV0ZHYUZwV2JIQlFWV3BHYTJSR1NuTmpSbVJPVFZWc05sWXhVa3RPUmxwMFZteG9WMkV4Y0ZsWmJHaFRWREZhYzJGRlNtdE5WbkJKV2xWa1IxWnJNVmRpUkZKWFRXNW9XRlpxU2tabFJrNXpZVVpXVjJWc1drVldWM1JoWXpBMWMxTnVTbXRTYXpWUFZteG9RMDVzWkZkV2JYUlRUVlpXTkZkclZtRldSMHBIVTJ4b1ZtSllhR2hXTUZwclZqRndSMVJzWkU1V2JrSmhWMVpXWVdFeVJraFdibEpzVW14S1dWWnFUbE5qVmxKelZsaGtiRkl3Y0VwVk1uaHJZVlpLVlZac2FGaFdNMUpvV1hwQk1WWXhaSE5oUjNSVFVsVndXVmRXYUhkU01VNUhWMWhzYTFKR1NsbFpiRlpoWlZaWmVVNVlaRmRXTUhCYVdWVmFVMWRyTVhWVVZFWlhZbGhOZUZadGN6RlhSMFpHVGxkc2FWWlVVWGhXYlRCNFRrWlZlRlJ1VWxkaE1YQlBWbXhrVTFac2JIUmpla1pYVm0xNFZsVnRNVWRXYXpGWVpVaHdWMVl6YUhKWlZWcExZekZrZFdKR1pHbFdSbHA1VjFkMGExTXhUbGRTYmtwb1VtMVNjRlZxU205TmJGcHlWV3QwVkUxVmNIbFViRnBYVlcxS1NWRnJPVlpoYTFwTFdsZDRhMVl4WkhSa1JsSk9WakZLV1ZkWGNFOWtNa1p6VTI1U2FGSjZiRlpXYlhoM1RURmFWbGR0UmxOTlYxSXdWVzE0VTFSc1dsVldhMnhYWWtkTmVGWnFSbHBsVms1ellVZDRVMkpHY0ZoWFZtUXdXVlpTUjJOR1pGaGlWVnBaVld4U1IxWnNXbGhsU0dSWFRWWndSMVl5ZUhOWFJscHpVMnhDV2xaRmNFaFZha1pQWXpKS1IxZHRiR2hOTUVwdlZqRmtNRmxYVVhoVmEyUlhWMGRvV1Zsc1ZtRmpiRlp6Vld0a1dHSkhVbmxYYTJNMVZsZEtSMk5HY0ZaV00yaDZWbXBHWVZKdFNrVlViRlpwVW01Q05sWnRjRWRVTWsxNVVtdGtXR0pYYUU5WmExWjNZakZaZUZkdGRFNVNNVVkwVm0xMGEyRnNTbGRqUm14YVlrWmFhRmt5ZUdGalZrWlZVbXhTVjJKclNraFdha2w0VFVaYVdGSnFXbE5oYTBwWVZtMHhiMDB4V25GVGEzUllWbXRhZWxWWE1VZFZNVXBYWTBaQ1dHSkdXbkpXUkVaTFl6RndTVlZ0ZUZOaGVsWlpWMVpTVDFFeFdsZFhXR2hZWWxSc2NsUlhjM2hPVmxwSVpFZDBWMkpWY0VsWlZXaEhWbTFLVlZKc1VscE5WbkJVVm1wR2EyTnRVa2RVYXpWWFltdEtTMVl5ZEZkV2F6VlhWMWhvV0dKR1dsUlpiVEUwV1Zac1ZWSnJkRmhTYkhCNlYydFdNRlpHU25OWGJGcFdWak5vY2xaVVNrdFRWa1p5WVVab2FFMVZjRWxXYTFKTFZHMVdSMU51VmxWaVdFSlVWRmN4YjJSc1drZFpla1pXWVhwR1NGWXhhRzlaVmtwR1UyeG9WVlpXU2xoVk1GcFdaVmRTU0dSR1drNWhNMEpLVjJ4V2EySXhXblJUYTJob1UwWndXRlJWV25kbGJIQkdXa1U1VDJKRldubFViRnBQWVZaSmVscEVXbGRpV0VKTVZGVmtSbVZXU2xsaVJsSm9UVzFvVWxadGRGWk5WbXhYWWtaV1UySlZXbGhWYlhoM1YxWndWbGR1WkdsU2JIQjZWakkxYzFsV1NsZGpSMmhYWVd0YVRGWnRNVTlTYlVwSFlVWmtiR0V4VmpOV2JYUlRVakZzV0ZSWWFGZGliRnBWV1d0YVMyTkdXbk5YYm1SV1VteHdXVmt3VlRWaFZURldZMGh3VjAxdWFISldNR1JMVjFaV2RFOVdWbGRpUmxZMFYyeGtORll5VFhsU2EyaHJVbXh3VDFsVVRrTldNVnAwVFZSU2FrMVhVakJWYkdoelZtMUtjMk5IYUZaaGF6VjJXbGQ0V21ReGNFZGFSbEpYWW10S1NWZFdWbUZoTWtaR1RWWnNVbFpGU2xoWmExcDNZMnhTVmxwR1NteFNiSEJhV1ZWYWIyRlhSalpXYmxwWFVteEtURlpVUm10U01WWnpXa1pvYUUweFNsZFdWekUwWkRKV1IxWlliR3hTV0ZKd1ZXMTRkMlZzV1hsT1dFNVlZa1p3V1ZaWE5YZFdNa1Y0WTBWNFlWSnNjRWhhUmxwM1VqSkdSMXBIYkZkV1Jra3lWbTEwYTA1R2JGZFdXR2hVVjBkb1YxbHRjekZYVm14eVYyMUdhVTFXU2xkWlZWWlBZVlV4VjJORmFGZGlWRVYzVmtSR1MyTnRUa2RoUm1ScFYwZG9lVll4V21GVGJWWnpWbTVPVjJKSVFtOVVWbHAzVjFaYVIxVnJaRmROYkVwSFZGWldWMVV5U2toVmJGSmFZVEpvUkZZd1dtRlRSMVpIV2taV1RsWXhTa3BXVnpBeFV6RmFTRk51VmxKaVIxSmhWbXRXWVUweFZYZFhiSEJyVFZkU01WZHJXazloVmxwVlZtdHNWMVpGY0RaVVZscFdaVVprZFZac1NsaFNNbWhaVjFkMFlWTXhUa2RYYmtaVFlrVndjMVZ0ZEhkWGJHeHlWMnM1YUZZd2NFZFpNRnBoVmpKR2NsTnVTbFZoTVhCWVZXcEdhMlJXVG5OYVIyaE9UVlZ3TTFacldtRlpWMUYzVFZaa2FFMHlVbGxaYkZaaFkwWldkR1JJWkU1U2JIQlpWR3hvYTFZeVNsWmpSbHBYWWxSR2RsWXdXbUZqTVZweFZXeGFUbEl4U2xsV1Z6RTBXVmROZUZwSVRtRlNNbmhZV1ZST1FrMVdXblJsUms1VVRVUldTRlV5TlZOV2JHUklZVVpXV21KWWFFeFdWVnBoWkVkV1JtUkdhRk5pU0VJMlZteGtOR0V4VlhoVGJrNXBVa1phWVZSVldtRlZSbXhZWXpOb1YySlZOVWRaVlZwaFlWWmtTR0ZFU2xkTlZuQm9WWHBHYTFZeFNuVlViRlpwVW14d1dWWnRNVFJrTWtsNFdraEtXR0pWV205VVZscHpUa1prY21GR1RtaE5WWEF3V1ZWb1ExWnRTblZSYm14VlZteHdhRmt5ZUhkU1ZrWjBZa1UxVjJKR2EzaFdiRkpLVFZaWmVGWnVVbFJpYTNCWldXdGFkMWRHYkZWU2JVWk9UVlp3ZVZZeWVFOVhSa2w0VjJ0d1ZrMXFSVEJXYWtaaFVteGtjMkpHWkZkU1dFRXlWa2Q0YTFJeFNuSk5WbHBYWWtkU2IxbFljRmRYVmxwMFRWUlNhMDFyTlhwWmExcFhWVEpHTm1KSVJsVldiRm96VmpKNGEyTnNaSEpQVjJoWFlraENTVlpxU2pSWlZsbDVVMnhzYUZKdFVsWldiWGgzVWpGd1ZsZHVaRlJXYTNCNlZUSXhjMkZIVm5OWGJGcFhZa2RPTkZSVlduTldNWEJIV2tkR1ZGSllRbGxYVnpCNFZURlplR0pHYkdwU1YxSlVWRlphYzA1V1VuTlhiWFJYVFd0Wk1sVnRlRzlXTURGMVlVVlNWMkpZYUdGYVZ6RkhVbFpPZEZKc1RsTlhSVXBPVm14amVFNUdXWGxVV0doVlltczFhRlZzVWxkalJsWnpZVVZLVGxac2NEQmFWVnBQVldzeFYySkVWbGRXZWxaTVZrZDRZV1JHVm5OYVJtUk9VakZGZDFkV1ZtRldiVkY0V2toV1lWSXlhRlJaYTFaM1YwWlplV1JHVGxaTlZsWTBWakkxVDFkSFNraGhSbXhhVmtWd1UxcEVSbUZqYkhCR1pFWk9hVkp1UWpSV2EyUTBXVmRHVjFkcldsTmhiRXBZV1d4b1UyRkdaRmRYYlVacVlYcFdXRll5ZUZkaFZrbDVZVWhhV0Zac1NrUmFSRUV4WXpGa2MyRkhkRk5OUm5CVlZrWmFhMVV4VGtkaE0yUlhZbFZhYjFsclZuZGxWbXQzVmxSV1YySlZjRWhaTUZKUFZsWmFjMk5IYUZkaVJuQk1XWHBHZDFJeFduSk9WbVJYWW10RmVWWnFSbXRrTVZGNVVsaHNVMkpIVWxWWmEyUlRWbFpzY2xaVVJsaFNiWGhaV2tWb2ExWXhTbk5YVkVwV1lsaG9jbFpxUm1GamJHUjFZa2RHVTFac1ZqUldhMlEwVjIxV1IxUnVUbWxTYldoWVdXdGFkMWRHV2tobFIzUlVUVlUxU0ZaSE5VdFhSMHBZWlVaU1ZtSllhRE5XYWtaaFVqRmtkR1JIYkU1aE1YQkpWakowWVdFeFdYaGFSV2hvVTBWd1dGbFhkRXRoUmxWNVpVZEdWRkl4V2toWGExcGhWRzFLUjJORVdsZGhhMnQ0V1hwR2ExTkdUbkphUjNCVVVsaENXRmRXWkRCWlYwNXpWMjVHVTJKVlduSldiWGhoVFVad1ZsZHJPVmhTYTJ3MVdWVmFWMVl5UlhoalJtaGFZV3RhUjFwV1dsTmpiSEJIV2tab1ZGSlZjRFJXYkdRMFdWZFJlVlJ1VGxaaVIxSmhXbGQ0WVZWR1ZuUmxTRTVQVm01Q1YxZHJVa05XTURGV1lrUk9WMDFXU2t4V2JURkxWMWRHUm1GR1pFNWliV2h2VjFod1IyRXlUblJTYTJScVVqTm9iMVJXYUVKTlZsbDVaVWR3YkZKck1UUlZNalZQVm0xS2NrNVlSbFppUmtwWVdXcEdVMVpXUm5KalIzaHBVbTVDTmxacVNYaFNNa1pHVFZoS1YyRnNTbGhWYm5CWFZVWmFWVkp0ZEZSU2JGcDZWbTE0ZDJGRk1YTlRiRlpYVFZad2FGcEVSbXRUUmxaeVlrZEdVMkpYYUZWWFZ6RXdVekZrVjFkWWJHdFNiVkpQVldwQ1YwNUdWWGxPVlhSb1lrVndSMVl5ZUc5V01rcDFVV3RvVmsxR2NHaFpNVnBMWTIxU1JrOVhiRmRYUlVwTVZtMHdlRTVHYkZkVmJsSlVZbXhLYjFWclZuZFhSbXhWVTJ4S1RsSnVRa2xVVmxwclZrWktjbU5JYkZkTmFrWjJWbFJHWVZOSFZrZFdiR1JUWWxaRmQxWlljRWRWTVVsNFdraE9ZVkpzY0c5VVZWSlhWbFphUjFwRVFtdE5iRnA2VmpGb2MySkdTWGRYYlVaWFlsaFNNMVl4V21GWFJUVldUMVpvYVZaWVFrbFdiVEYzVlRGYVdGTnNiR2hUUlhCaFZGZHdSMU5HVlhkWGEzUnJVakJhU1ZscldtdFhSa3BXWTBkR1YySllhSEpVYTFwV1pVWlNXV0ZHYUdoTmJFcGFWMWQwWVdReFZrZFhibEpPVm5wc2IxVnRlSGRsUmxwSVpVVTVhVkl3Y0VoV01qVnZWbXN4ZFdGSVNsZGhNWEJvV1hwS1QxTlhTa2RqUlRWVFRWVnZlVlp0TVhkU01XeFhWMWhzVldFeFdsbFphMlJUVjBaV2MxZHVaRmhXYkhCNVZsZDBNRlpIU2xkWGJHaFhUV3BXVUZkV1drcGxiRVp6Vld4d2FWSXlhREpXYlhCSFlURlplR05GVmxKaVNFSllWRlZTVjFOV1duUmxSemxvVFZkU1NWVnNhSGRXYlVwVllrWm9XbUpIYUhaV1JWcGhZMVpLYzJOSGVGTk5SbkJLVjJ0V2EySXlSa2hXYmtwWVlUTkNXVmxyV21GWFJuQkZVbTFHYW1GNlJscFZiWGhQVmpGS1ZtTkhhRmRpV0VKUVZrUkJkMlZIVGtkWGJHaHBWMFpLZVZadGNFSk5WazVYVm01U2JGSlViRmhVVjNSM1pWWldjMkZJVGxkTlJFWXhXVlZhYjFkR1duUlZhM1JoVmxad2Nsa3lNVWRTTVdSellVWk9UazF0YURKV2JYaHJaREZSZUZKWWFGaGhNbEpYV1d0YWQxZFdiSFJsU0dSVlRWZDRlVmRyV2s5WFIwcElaRVJPVjJKR1NsaFpWVnBMVmxaS2RXTkdXazVpYTBwRlZtMXdSMU13TlhOWGJrNVdZa2RTY0ZZd1pHOWxWbHBZVFZSU1ZVMXJOWGxVVmxwcldWWktkRlZ1UWxkaVJrcEVWR3RhV21WR2EzcGhSVGxUWWtWWk1GWnFTVEZVTVZwMFUyNUthbEpzV21GWmExcGhZVVphUlZKc1pHcFdiRW93VkRGYVQyRldTblZSYkd4WFlXdHNORlJWWkVkU2F6RlhWMnM1V0ZORlNsaFhWM1JyWWpKT2MxZHNWbFJoTTFKWVZtMTRkMlZzV25SbFIzUm9WbXR3ZWxadGNGTldNVnB6VTJ0b1dsWkZjRkJXYWtaTFpGWmFjMVp0YkZOV1JscFdWakZhVTFJeVVYaGFTRTVZVjBkNGNsVnRNVk5qYkZKWFYyMUdiRlpzU2xoV2JURkhWMFpKZDJOSWNGZE5ibWh5Vm14YVlXTXlUa2hoUm5CT1ltMW9iMWRVUm1GU01WcFhVMjVPVldGNlZtOVVWbHB5WlZaWmVGcEVRbHBXTUZZMVZXMTRiMVpIU2toVmJGWmFZbFJGTUZZd1dtRmtSMVpHWkVaT1UySkdhM2xXVnpFd1pESktSMU5ZWkU5V1YyaFlWRmR3UjFOR1dsVlNiVVpVVWpGYVNsZHJXbXRXTURCM1UydFNWMUpzY0doV1JFcE9aVVp3U1ZSdGFGTldSM2haVm0xNFUxWXlVbk5YYmxKc1VtczFWRlJYZUdGVFJsbDVaVWQwVjJKVlZqWldWM2hyVjJ4a1NWRnJhRlZXVm5BelZtMTRZV05yT1ZkaFJrNU9VbTVCTVZac1VrcE5WMUY0VjI1U1UxZEhhSEZWYkdSdlYwWlNWbGR1WkU1TlZsb3dWRlpWTlZVd01WWk9XR3hWWWtad1VGWnFTa3RqYkVweFZXeGthVmRIYUZWV1YzQkhWMjFXUjFac2JHaFNhelZ3V1Zod1YyUXhXa2RWYTNSV1RXczFTRlp0TlU5WFIwVjZWV3hrVlZac2NETmFWVnBXWlZkV1JrOVdaRk5XUlZwWlZtcEtORmxXV25OWFdIQldZbXR3WVZadE1WTlVSbFowWTNwR1YwMVlRa2hYYTFwUFZHc3hWbU5GTlZkaGExcG9WbTB4VjFJeFVuSmhSbVJvVFZoQ1dWZFhkR0ZrTVdSSFlraE9XR0V6VW5OV2JYaDNWbXhWZVdOR1RsZFdWRVpYV1RCb2QxWXhTalpXYkZKWFZsWndhRnBHV2tka1ZsSnpZMFpvVkZKVmNGcFdiWGhYV1Zac1YxcEdhRlZoTVhCV1dXeG9RMVF4V25OaFJVNVVWbXh3V1ZSV1VsTmhWVEZZWlVab1ZrMXVhSHBXVnpGTFVtczFWMWRzWkdsU2JrSnZWMVpXWVdReFNYaGFTRTVZWWxob1ZGbHJhRU5PVmxwRlVtMUdWRTFyV2xoVk1uQmhZVVV3ZWxGc2JGZGhhelZVVmpCYVlWWldTbk5hUjNCT1ZqRktZVmRYZEdGWlYwWllVbGhvYWxKdGFGbFdiVEZTWkRGV05sTnJaRk5OVmxveFZsY3hORlpHU2xWV2JFWllWak5TV0ZkV1ZYaFNNazVHVjIxR1UxSlZjSFpXYlRFMFpERmtWMk5GYkdwU1YxSllWRlZTUjAxV1dsaE9WMFpYVFZWd1IxWXlOWGRXTWtaeVYyMW9XazFXY0hKWmVrWjNVMGRLU0dGRk5WaFNWWEF5Vm0xd1IxbFdWWGhVV0doV1ltdHdUMVp0TVZOalZsWjBUVmM1YWsxV1ZqTlhhMXBQVjBaS2MxZHFRbFZXVmtwWVZrUktTMUl4WkhOaVIwWlRWbTVDVVZacVNqUlpWbHBYVTI1V2FGSnVRbTlVVmxwYVRVWmFkRTFZY0d4U2JWSkpWVzEwYzJGc1NuTmpSbWhXWWtkb1JGWkdXbUZqVmtaMFVteFNUbUY2UlRGV1ZFb3dZVEZhZEZOc2FHeFNiWGhYV1ZkMGQyUnNXa2RYYlVacVRWWmFlVlpIZUhkV01rWTJVbFJHVjJKSFRYaFdSRVp6VmpGU2NsZHJPVmRpU0VKb1ZtMTBWMUp0VmtkaE0yeHNVbXMxV0ZSV2FFTlNiRnBZWlVjNWFGWnJiRFpaVlZKWFYwWmFjMWRzWkZWaVIxSklWV3BHYTJNeFduTlViV3hwVjBkb1dsWnJXbXRrTVZsNFZXdGtXR0pIYUhGVVZFcHZZMVphZEdSSVpFNVNiWGhYVmpJMWExWlhTa1ppUkZKV1RXNW9TRll3WkVabFJtUjBZVVpvVjJKSVFubFdWekY2VGxaWmVGcElVbXhTYXpWd1ZUQldTMWxXV25OYVJGSlhUVmRTTUZadE5VOVhSbVJJWVVac1dtSkdXbWhaYWtaell6RmtkRkpzVWxkaVJsa3hWMnRXYTFJeVJsZFRia3BQVmxkb1dGUlhOVzloUmxsNVRWVjBXRlpzU2xwWlZWcDNWakZhZFZGdE9WaFdSVnBvVlhwS1UxSXhUblZUYXpsWFZrWmFXVlp0ZEZkV01EVnpWMjVTYkZJelVsQlZiVEUwVjFaV2RFNVZPVmRTTUhCSVdUQmFRMVl3TVVoVmJGSlhUVVp3V0ZwRlZYaFdNVkowWTBkc1UwMHlhR0ZXTVdoM1ZESkplVkp1U2s1V2JXaFhXV3RvUTFkV2JGVlNibVJYVW14d2VGVnRlSGRpUmxsM1YydG9WMkpZYUhaV2FrRjNaREZPY21KR2FHaE5WWEJKVmpGYVlWTnRWa2RVYmxaWFlrZFNjRlpxVG05V1ZscEhWbTFHYTAxWFVsaFdNblJyV1ZaT1NWRnJPVmRoYTFwTVZqQmFhMk50Umtaa1JtaG9aV3RKTVZkV1ZtRlZNVnBYVjFod1ZXRnNTbFpaYTFwM1lVWlpkMXBHWkZSU1ZHeFlWMnRWTVZZeVNsbFpNMmhYWWxob2NWcEVRVEZXTVdSWllrWlNhV0pHY0ZSWFYzUmhVekZzVjJKSVRtaFNlbXh6Vm0wMVExZEdXbk5WYTJSWFRVUkdXbFZYZEhOWlZrcFhZMGhLVjJGclJqTmFWbVJIVW0xU1IxcEZOV2xpUlhCYVZqRmFVMUZyTVZkVWEyUlZZbXR3YUZWdE1WTmpSbFp4VkcwNVYxSnRVbGhYYTFKVFlUQXhXRlZzYUZwaE1taE1WMVphUzA1dFNrZGhSbHBwVmtWYVZWWkdWbUZWTVZsNFYyeFdWMkpYYUU5V2JHaERUbXhrVlZGc1RsSk5WbkJaVlRKMGEyRnNUa2xSYkdoV1ltNUNTRlpGV25OT2JFcHlUMWQwVjAxRVZrbFhWbFpyWXpGVmVWTnVTbFJpVkd4WVdWUktVazFHV25STlZtUlVVbXhLV2xscldsTmhSVEZ6VTI1YVYxWXpRbEJaYWtaaFVqRmFkVlJzYUdsaVZrcDNWa1phWVdReVZuTlhiR2hyVWtWS2IxWnNVa2RYUm10M1ZtMDVWMDFyY0ZaV2JYaERWakpHY21ORmVGZE5WbkJZV2tWa1IxSXlUa2hoUlRWWVVsVndNbFp0ZUd0a01VbDRWMWhzVm1FeWFGaFpWRXBUWVVaV2RFMVdUbGRTYlhoV1ZXMTRkMVJ0U2toVmJHaFhZbFJHU0ZadGMzaFdNazVGVVd4YVRtSnNTbmxXYWtKclV6Sk9kRlJyWkdsU2JrSndWV3BLYjAxc1duUmtSMFpxWWxaYVdWWnRkR0ZoTVVsNlVXMDVZVll6YUdoV01WcGhZMnh3UlZWc2NGZGlSWEExVmtaYWIxVXlSa2RUYms1cVVtMW9ZVmxVU2xOVk1WSldWMjFHYWxack5YbFdNakUwVlRBeFJWWnJkRmRoTWxFd1dXcEtSMWRHU2xsalJrcHBVbXh3V2xadE1IaGlNREI0Vm01R1UySllVbFJVVm1SVFRWWmFTR1ZIT1doV2EydzBWVEkxYzFZeFNuTmpSbWhYWVd0RmVGWnFSbmRUVms1MFlVWk9UbEp1UWpKV2JHUjNVVEZaZDA1V1pHcFNiSEJZV1cxek1WZEdVbGRYYms1UFlrWmFXVnBGWXpWWFIwcEhZMGh3V2sxSGFFeFdiVEZMVjFkR1JtVkhSbE5XYkZZMFZtMXdTMUl4VGtoU2EyaG9VbFJXY0ZsWWNGSmtNVnAwWTBWMFRsSXdWak5VYkZadlZtMUtjMU5zYUZwaE1sSjJWakJhYzFaV1RuUlBWM0JPVm14d05sZFdWbGRVTVZsNFUyNU9WR0pIVWxoV2FrNXZZMnhhU0UxVmRGUlNiRnA2VmpKNFlWUnNXWGxoU0d4WFlURktTRll5TVZkU01WSjFVMjFvVTJKclNsQldWekF4VVRGYVYxZHVUbHBOTW1oVlZGZDRTMU5HV25ST1ZrNVdUV3R3U1ZaWGN6VldiVXBaWVVab1ZXRXhjR2hWTUZWNFZsWldkR1JGTlZkWFJVcGFWbTEwYTA1R1dYaFhXR3hVWWtkNGIxVnRNVzlaVm14ellVWk9WVkpzV25sV01qRXdWakZhY2xkcVFtRlNWbFY0VmxSQmVGSXhaRlZSYkdSb1lUTkJlbFl4V21GV2JWWlhVMjVXVkdGNmJGaFpiR2h2VjBaa1YxVnJaRnBXVkVJMFdWUk9jMkpHVGtoVmJGWldZa1pLU0ZacVJuSmtNWEJGVld4a1RtRXpRalZXVkVvd1RVWlplVkpZYkZWaGJFcFhXVmQwWVZsV2NGZFhhM1JyVm14YU1GcEZWVEZVYXpGR1kwWndWMkV4Y0doWFZtUlNaVlpXZFZSc2FHaE5WbkJXVjFkMGExVXlUbk5XYmxKc1VqQmFXVmxyWkRSbFZsbDVaRVU1V0ZKcmNIbFphMUpoVjJ4YVdGUlVSbGRoYTFwb1dYcEdUMk50VmtkalJtUlRWMFZLVlZZeWVGZFpWazE0V2tab1ZHRXlhRlJaYTFwTFZrWnNkR1JGZEU1aVJtdzBWako0VDFaRk1VVldhMmhYVWpOb2NsbFhlRXRXTWs1SVlVWmFhRTFZUWsxV01WcGhXVmRTUmsxV1pGVmlSVFZQVm0xNGRtUXhXa2RXYkU1VFRWZFNTRlV4YUd0aGJFcHpZMFprV21KR1NsaFVWRVpyVmpGa2RGSnRkRk5pUm5BMVYxWldZV0V4VW5OVGJrNVhZV3hLV0ZsWGRFdFdNVkpYVjIxR2ExSnNTbmxYYTFwWFlVZFdjMWR1WkZoV00yaHlWbGR6ZUZJeFpIVlViRnBvVFd4S1dWWkdaREJXTURWSFYyeGthRk5GTlZkVVYzUlhUbFpzVmxkdFJsZE5SRVpKVmxaU1ExWXdNVWRqUjJoYVRWWndVRmw2UmxOa1IwNUhWRzFzVTFkRlNtaFdha28wVmpKSmVGVlliRk5pUjJoVldWUktORlV4YkZWVGJFNVlWbTE0VmxVeWN6RlViRnAwWlVab1YwMXVVWGRXTUZwS1pVWmtjbHBHY0doTldFSjVWbXhTUzFZeVRYaGFTRkpRVm0xb1dGbHJhRU5sVmxwWlkwVmtXbFpzYkRSWGEyaFhWakpLUjFkdVFsWmhhM0IyVmpGYVlWZEhWa2RVYkdST1ZtNUNXVll5ZEdGV01WWjBVMnhzVm1KR1dtRlphMXAzWVVaYWNWSnNUbXBOVm5Bd1ZERmFkMVl5Ulhsa2VrWllWbXhhYUZsNlJtRmtSazV5V2taU2FFMXRhRzlXVnpFMFpESk9jMWRZWkdGU2F6VlZWV3BCTVZJeFVYaFhiWFJWWWtad01GUXhVazlXTWtwWlZXNUtZVkpGV2xOYVZscExaRlpTYzFWdGFFNVhSVXBTVm0wd01XUXlUWGhYV0docFVtMW9jbFV3V25kVU1WWjBUbFZPV0ZadVFsZFhhMUpEWVVkR05sSnNhRlpOYWxaNlZtcEdTbVZ0UmtsVGJHUm9ZVEJaTUZaWGVHRlpWbVJZVW10a1lWSXllRmhWYkZaeVpERmFjbHBFUWxwV2JHdzBWVEZvYzFaR1pFbFJia0pXWWxoU1RGWXdXbmRYUjFaSVVteGthVkp1UVhkWGJGWmhXVlpTYzFkdVNsZGhiRXBaV1ZSS2IxTkdXbkphUldSUFlsVndTbFV5ZUd0aFZtUklXak53VjFKc2NHaFhWbVJUVTBaYWNtSkdWbWxTYkhCM1ZtMTRZVmRyTVVkYVJsWlNZa1UxVTFSV1pGTlRWbFp6WVVjNVdGSXdjSGxaTUZwdlYyeFplbFZxVGxkTlJuQm9XVEZhUzJSV1pIUmxSMnhYVjBWS1NsWnRNSGRsUjAxNVVtdG9WMkpyTlZsWlYzTXhWMFpzVlZKdVpGZFNiRnBaV1hwT2IxZEdTbk5UYkhCYVZsWndXRll3V2twbFJrNXpXa1pvVjJWclZqTlhhMUpIV1ZaWmVGWnVUbGhpVlZwVVZXMTBkMVpXV25STlZGSmFWbTFTU0ZkcmFFdFpWa3BHVTJ4b1ZtRnJTak5WYWtaVFl6RmFkRTlXWkdobGExbzBWbTB3TVZNeFdYZE5XRVpUWVROb1YxUlZXbmRYUm13MlVtNWtWRkpyY0hwV1J6RnpWakpGZWxGc1NsZGhhMjh3VjFaa1JtVkdaRmxoUmxab1RXMW9XVmRXVWt0aU1WcEhZa2hLWVZKNmJGaFZiWGgzWld4WmVVNVhSbWxTYkhCNldUQlNRMVpXV25OVGExSlhZV3RHTkZreWMzaFdWbFp6V2taa2JHSkdjRkpXYlRFd1lURk5lRlJyWkZkaWF6VlVXV3RrVTJOR1dYZGFSemxWVm14d01GUldVbE5XTURGeVRWUlNXR0V5YUZSV1ZFcExVbXMxVms5V1pHbFdSbHBGVm1wQ1lWbFhUbk5pUkZwVFlrWktUMVp0TlVOVGJGcHpXa2hrV2xac1NucFZNblJ2WVcxV2R' in content:
        detection += '🕴️' + ('viRu5.GoogleChromeAutoLaunch(autostarts when Chrome boots)')
        Score = Score + 55
    return {"Score":Score,Score:detection}

class scan(object):
    """Scan a file's Bytes for Malware!"""
    def __init__(self, Content):
        super(scan, self).__init__()
        data           = _cscan(Content)
        self.Score     = data["Score"]
        self.Detection = ','.join(data[self.Score].split('🕴️'))
        self.Content   = Content
