#Script

#Inquisitor1

import logging, sys
import requests, os
import hashlib
"""
#get the Inquisitor's latest hashes
curhash = requests.get('https://raw.githubusercontent.com/MoraByte2027/Inquisitor/main/Version').content.decode().split("\n")

#get this Inquisitor's hash
filehash = hashlib.sha256(open(sys.argv[0], 'rb').read())

#potato salad
if filehash != curhash[0] and open(sys.argv[0], 'r', encoding="ISO-8859-1").read().split("\n")[0] != '#Script':
    print(f"Updating...")

    link = requests.get('https://raw.githubusercontent.com/MoraByte2027/Inquisitor/main/Latest').content.decode().split("\n")[0]
    open(sys.argv[0], 'w').write(requests.get(link).content.decode())

    os.system(f'{sys.argv[0]}')

    sys.exit()
elif open(sys.argv[0], 'r', encoding="ISO-8859-1").read().split("\n")[0] == '#Script' and filehash != curhash[1]:
    print(f"Updating...")

    link = requests.get('https://raw.githubusercontent.com/MoraByte2027/Inquisitor/main/Latest').content.decode().split("\n")[1]
    open(sys.argv[0], 'w').write(requests.get(link).content.decode())

    os.system(f'{sys.argv[0]}')

    sys.exit()
"""
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

def cscan(file, Score=None):
    if not Score:
        Score = 0

    count = 0

    content = open(file, 'r', encoding="ISO-8859-1").read()
    logging.info('┍file')

    count = count + 1
    x = (content.find('Rar! '))
    if x > -1: logging.info('┝RarPacked')
    if x > -1: Score = Score + 3
    x = (content.find("7zÂ¼Â¯' "))
    if x > -1: logging.info('┝7zPacked')
    if x > -1: Score = Score + 3
    import zipfile
    if zipfile.is_zipfile(file) == True:
        zip = zipfile.ZipFile(file)
        for name in zip.namelist():
            f = zip.open(name)

            cscan(f.read(), Score)

    x = (content.find('æŒ¦ç ¬à¨ '))
    if x > -1: logging.info('┝Obfuscated')
    if x > -1: Score = Score + 3
    x = (content.find(':BFP'))
    if x > -1: logging.info('┝Obfuscated')
    if x > -1: Score = Score + 4
    x = (content.find('hatsploit'))
    if x > -1: logging.info('┝Hatsploit')
    if x > -1: Score = Score + 3
    x = (content.find('net user \%username%'))
    if x > -1: logging.info('┝NetPassword')
    if x > -1: Score = Score + 16
    x = (content.find('net1 user \%username%'))
    if x > -1: logging.info('┝NetPassword')
    if x > -1: Score = Score + 16
    x = (content.find('net share'))
    if x > -1: logging.info('┝NetShare')
    if x > -1: Score = Score + 7
    x = (content.find('net1 share'))
    if x > -1: logging.info('┝NetShare')
    if x > -1: Score = Score + 7
    x = (content.find('%COMSPEC% /C start %COMSPEC% /C \\WINDOWS\\Temp'))
    if x > -1: Score = Score + 3
    x = (content.find('bash -c \'exec bash -i &>/dev/tcp/'))
    if x > -1: logging.info('┝Bash')
    if x > -1: Score = Score + 3
    x = (content.find('zsh -c \'zmodload zsh/net/tcp && ztcp'))
    if x > -1: logging.info('┝Zsh')
    if x > -1: Score = Score + 3
    x = (content.find('zsh >&$REPLY 2>&$REPLY 0>&$REPLY\''))
    if x > -1: logging.info('┝Zsh')
    if x > -1: Score = Score + 3
    x = (content.find('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc'))
    if x > -1: logging.info('┝NCat')
    if x > -1: Score = Score + 3
    x = (content.find('TF=$(mktemp -u); mkfifo $TF && telnet'))
    if x > -1: logging.info('┝telnet')
    if x > -1: Score = Score + 3
    x = (content.find('0<$TF | /bin sh 1>$TF'))
    if x > -1: Score = Score + 3
    x = (content.find('bash -c \'echo -e "POST / HTTP/0.9 $(<'))
    if x > -1: logging.info('┝BashHttp')
    if x > -1: Score = Score + 3
    x = (content.find('> /dev/tcp/'))
    if x > -1: logging.info('┝BashTCP')
    if x > -1: Score = Score + 3
    x = (content.find('D$UPPPj'))
    if x > -1: logging.info('┝Mimikatz')
    if x > -1: Score = Score + 19
    x = (content.find('D$Ej'))
    if x > -1: logging.info('┝Mimikatz')
    if x > -1: Score = Score + 19
    x = (content.find('|$JQu0'))
    if x > -1: logging.info('┝Mimikatz')
    if x > -1: Score = Score + 19
    x = (content.find('D$CjNh'))
    if x > -1: logging.info('┝Mimikatz')
    if x > -1: Score = Score + 19
    x = (content.find('|$BQun'))
    if x > -1: logging.info('┝Mimikatz')
    if x > -1: Score = Score + 19
    x = (content.find('taskhcst'))
    if x > -1: logging.info('┝wannacry')
    if x > -1: Score = Score + 19
    x = (content.find('lsasvs'))
    if x > -1: logging.info('┝wannacry')
    if x > -1: Score = Score + 19
    x = (content.find('cscc'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    if x > -1: Score = Score + 19
    x = (content.find('infpub'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    if x > -1: Score = Score + 19
    x = (content.find('perfc'))
    if x > -1: logging.info('┝Petya')
    if x > -1: Score = Score + 19
    x = (content.find('taskkill'))
    if x > -1: logging.info('┝taskkill')
    if x > -1: Score = Score + 3
    x = (content.find('pskill'))
    if x > -1: logging.info('┝taskkill')
    if x > -1: Score = Score + 3
    x = (content.find('pskill64'))
    if x > -1: logging.info('┝taskkill')
    if x > -1: Score = Score + 3
    x = (content.find('tskill'))
    if x > -1: logging.info('┝taskkill')
    if x > -1: Score = Score + 3
    x = (content.find('C:\\Windows'))
    if x > -1: logging.info('┝SystemTamper')
    if x > -1: Score = Score + 3
    x = (content.find('C:\\Windows\\System32'))
    if x > -1: logging.info('┝SystemTamper')
    if x > -1: Score = Score + 1
    x = (content.find('csrss'))
    if x > -1: logging.info('┝SystemTamper')
    if x > -1: Score = Score + 4
    x = (content.find('wininit'))
    if x > -1: logging.info('┝SystemTamper')
    if x > -1: Score = Score + 4
    x = (content.find('svchost'))
    if x > -1: logging.info('┝ServiceTamper')
    if x > -1: Score = Score + 4
    x = (content.find('msmpeng'))
    if x > -1: logging.info('┝ProtectionTamper')
    if x > -1: Score = Score + 4
    x = (content.find('ntoskrnl'))
    if x > -1: logging.info('┝KernelTamper')
    if x > -1: Score = Score + 4
    x = (content.find('winlogon'))
    if x > -1: logging.info('┝LoginTamper')
    if x > -1: Score = Score + 4
    x = (content.find('socket.socket(socket.AF_INET'))
    if x > -1: logging.info('┝PYSocket')
    if x > -1: Score = Score + 3
    x = (content.find('wscript.exe /b /nologo /E:javascript'))
    if x > -1: logging.info('┝vbsjs')
    if x > -1: Score = Score + 3
    x = (content.find('Invoke-Mimikatz'))
    if x > -1: logging.info('┝Mimikatz')
    if x > -1: Score = Score + 21
    x = (content.find('copy \%%.*0'))
    if x > -1: logging.info('┝Copyself')
    if x > -1: Score = Score + 3
    x = (content.find('cacls'))
    if x > -1: logging.info('┝PermissionTamper')
    if x > -1: Score = Score + 4
    x = (content.find('takeown'))
    if x > -1: logging.info('┝PermissionTamper')
    if x > -1: Score = Score + 4
    x = (content.find('RMDIR'))
    if x > -1: logging.info('┝Deleter')
    if x > -1: Score = Score + 3
    x = (content.find('REPLACE'))
    if x > -1: logging.info('┝Replace')
    if x > -1: Score = Score + 3
    x = (content.find('ASSOC'))
    if x > -1: logging.info('┝assoc')
    if x > -1: Score = Score + 2
    x = (content.find('ATTRIB'))
    if x > -1: logging.info('┝Attributes')
    if x > -1: Score = Score + 3
    x = (content.find('FSUTIL'))
    if x > -1: logging.info('┝fsutil')
    if x > -1: Score = Score + 8
    x = (content.find('WMIC'))
    if x > -1: logging.info('┝wmic')
    if x > -1: Score = Score + 5
    x = (content.find('wbadmin'))
    if x > -1: logging.info('┝BackupTamper')
    if x > -1: Score = Score + 16
    x = (content.find('vssadmin'))
    if x > -1: logging.info('┝ShadowcopyTamper')
    if x > -1: Score = Score + 16
    x = (content.find('wmic shadowcopy'))
    if x > -1: logging.info('┝ShadowcopyTamper')
    if x > -1: Score = Score + 11
    x = (content.find('bcdedit'))
    if x > -1: logging.info('┝BootEdit')
    if x > -1: Score = Score + 16
    x = (content.find('bcdedit /delete'))
    if x > -1: logging.info('┝BootDel')
    if x > -1: Score = Score + 68
    x = (content.find('bcdedit/delete'))
    if x > -1: logging.info('┝BootDel')
    if x > -1: Score = Score + 68
    x = (content.find('php -r \'$sock=fsockopen(getenv('))
    if x > -1: logging.info('┝PhpSock')
    if x > -1: Score = Score + 3
    x = (content.find('powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\''))
    if x > -1: logging.info('┝PSSocket')
    if x > -1: Score = Score + 3
    x = (content.find('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect'))
    if x > -1: logging.info('┝PYSocket')
    if x > -1: Score = Score + 3
    x = (content.find('ruby -rsocket -e \\\'exit if fork;c=TCPSocket.new(ENV['))
    if x > -1: logging.info('┝RubyRSocket')
    if x > -1: Score = Score + 3
    x = (content.find('bash -c \'cat'))
    if x > -1: logging.info('┝BashCat')
    if x > -1: Score = Score + 3
    x = (content.find('nc -l -p'))
    if x > -1: logging.info('┝NCat')
    if x > -1: Score = Score + 1
    x = (content.find('nc -lnvp ;'))
    if x > -1: logging.info('┝NCat')
    if x > -1: Score = Score + 1
    x = (content.find('python3 -m http.server'))
    if x > -1: logging.info('┝PYHttp')
    if x > -1: Score = Score + 4
    x = (content.find('python -m SimpleHTTPServer'))
    if x > -1: logging.info('┝PYHttp')
    if x > -1: Score = Score + 4
    x = (content.find('scp pl'))
    if x > -1: logging.info('┝SCP')
    if x > -1: Score = Score + 4
    x = (content.find(':~/destination -P'))
    if x > -1: Score = Score + 3
    x = (content.find('scp user@'))
    if x > -1: logging.info('┝SCP')
    if x > -1: Score = Score + 4
    x = (content.find(':~/path_to_file file_saved -P'))
    if x > -1: logging.info('┝datpath')
    if x > -1: Score = Score + 5
    x = (content.find('document.cookie'))
    if x > -1: logging.info('┝HTCookie')
    if x > -1: Score = Score + 3
    x = (content.find('getItem(\'access_token\')'))
    if x > -1: logging.info('┝HTCookie')
    if x > -1: Score = Score + 3
    x = (content.find('UNION SELECT NULL,NULL,NULL'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('UNION ORDER BY 1'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('UNION SELECT @@version'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('UNION SELECT banner from v$version'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('UNION SELECT version'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('UNION SELECT table_name,NULL from INFORMATION_SCHEMA.TABLES'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('UNION SELECT table_name,NULL FROM all_tables'))
    if x > -1: logging.info('┝SQL')
    if x > -1: Score = Score + 7
    x = (content.find('System.Windows.Forms'))
    if x > -1: logging.info('┝WindowsForms')
    if x > -1: Score = Score + 7
    x = (content.find('PopUp'))
    if x > -1: logging.info('┝Popup')
    if x > -1: Score = Score + 3
    x = (content.find('[\\w-]\{24}\\.[\\w-]\{6}\\.[\\w-]\{27}" /c:"mfa\\.[\\w-]\{84}'))
    if x > -1: logging.info('┝Other')
    if x > -1: Score = Score + 21
    x = (content.find('hcrypt'))
    if x > -1: logging.info('┝Hcrypt')
    if x > -1: Score = Score + 7
    x = (content.find('/remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18'))
    if x > -1: Score = Score + 8
    x = (content.find('ConsentPromptBehaviorAdmin'))
    if x > -1: logging.info('┝UACAdminConsentPromptTamper')
    if x > -1: Score = Score + 8
    x = (content.find('HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\UX Configuration'))
    if x > -1: logging.info('┝ProtectionTamper')
    if x > -1: Score = Score + 8
    x = (content.find('Notification_Suppress'))
    if x > -1: logging.info('┝NotificationSuppresser')
    if x > -1: Score = Score + 8
    x = (content.find('DisableTaskMgr'))
    if x > -1: logging.info('┝DisableTaskManager')
    if x > -1: Score = Score + 7
    x = (content.find('DisableCMD'))
    if x > -1: logging.info('┝DisableCommandline')
    if x > -1: Score = Score + 7
    x = (content.find('DisableRegistryTools'))
    if x > -1: logging.info('┝DisableRegistryTools')
    if x > -1: Score = Score + 7
    x = (content.find('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies'))
    if x > -1: logging.info('┝PoliciesTamper')
    if x > -1: Score = Score + 8
    x = (content.find('NoRun'))
    if x > -1: logging.info('┝NoRun')
    if x > -1: Score = Score + 1
    x = (content.find('windefend'))
    if x > -1: logging.info('┝ProtectionTamper')
    if x > -1: Score = Score + 8
    x = (content.find('Add-MpPreference'))
    if x > -1: logging.info('┝ProtectionTamper')
    if x > -1: Score = Score + 8
    x = (content.find('Start Menu\\Programs\\Startup'))
    if x > -1: logging.info('┝Startup')
    if x > -1: Score = Score + 7
    x = (content.find('advfirewall'))
    if x > -1: logging.info('┝Firewall')
    if x > -1: Score = Score + 7
    x = (content.find('//4mY2xzDQo='))
    if x > -1: logging.info('┝CanObfuscate')
    if x > -1: Score = Score + 4
    x = (content.find('certutil'))
    if x > -1: logging.info('┝Certutil')
    if x > -1: Score = Score + 2
    x = (content.find('JKbtgdfd'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('510501002024'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_GentProcessID@0'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_ResumePhrocess@4'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_GetThureadList@12'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_SutspendProcess@4'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_GetPrkrocessList@8'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_GetPronhcessName@8'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_GetThrehjadContext@8'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_ReadRehmoteMemory@16'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_WriteRehmoteMemory@16'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_AllocahteRemoteMemory@8'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_GejtModuleBaseAddress@8'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_TerminatejbProcessByID@4'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('_CheckPirocessForString@8'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find('BACAIHJHUTVTWT[Zbadcecfcgchciclkrqsq}|~|'))
    if x > -1: logging.info('┝Agent Tesla')
    if x > -1: Score = Score + 8
    x = (content.find('3/9;h~lo/0jcdibnch-~~l]1'))
    if x > -1: logging.info('┝Agent Tesla')
    if x > -1: Score = Score + 8
    x = (content.find(' / a n'))
    if x > -1: logging.info('┝Ursnif')
    if x > -1: Score = Score + 7
    x = (content.find('ngTinC'))
    if x > -1: logging.info('┝Formbook')
    if x > -1: Score = Score + 4
    x = (content.find('adminToolStripMenuItem_Click'))
    if x > -1: logging.info('┝Formbook')
    if x > -1: Score = Score + 4
    x = (content.find('ngaySinh'))
    if x > -1: logging.info('┝Formbook')
    if x > -1: Score = Score + 4
    x = (content.find('soDienThoai'))
    if x > -1: logging.info('┝Formbook')
    if x > -1: Score = Score + 4
    x = (content.find('btn_Update_Click'))
    if x > -1: logging.info('┝Generic Malware')
    if x > -1: Score = Score + 4
    x = (content.find(')>-;8*#'))
    if x > -1: logging.info('┝Agent Tesla')
    if x > -1: Score = Score + 8
    x = (content.find('hycdhyl{d'))
    if x > -1: logging.info('┝Agent Tesla')
    if x > -1: Score = Score + 8
    x = (content.find('8SVWjnXjtf'))
    if x > -1: logging.info('┝Formbook')
    if x > -1: Score = Score + 4
    x = (content.find('encryptionAesRsa'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('checkStartupFolder'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('checkdeleteBackupCatalog'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('appMutexStartup2'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('appMutexStartup'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('surprise.exe'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('(?:[13]\{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('checkdisableRecoveryMode'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('checkdeleteShadowCopies'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('7z459ajrk722yn8c5j4fg'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('sleepOutOfTempFolder'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('1qw0ll8p9m8uezhqhyd'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('2X28tfRmWaPyPQgvoHV'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('copyResistForAdmin'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('checkCopyRoaming'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('17CqMQFeuB3NTzJ'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('addAndOpenNote'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('appMutexRegex'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('sleepTextbox'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('appMutexRun2'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('randomEncode'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('checkSpread'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('copyRoaming'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('appMutexRun'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('spreadName'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('appMutex2'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('spreadIt'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('addLinkToStartup'))
    if x > -1: logging.info('┝CHAOS Ransomware')
    if x > -1: Score = Score + 7
    x = (content.find('encrypted_key":"'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('[\%04i/\%02i/\%02i \%02i:\%02i:\%02i'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('0!0-070K0W0e0o0{0'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('606A6G6M6T6a6'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find(';+;=;I;Q;i;'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('L$,#L$ #D$,'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('T$$#T$(#D$$'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('m0~0a2l2|2'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('5<5B5G5M5^5'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('5(5N5f5l5'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('K j@^+s`;'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('u PPj7UPQ'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('C`UVWj@_'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('u:E;l$(|'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('L$ !t$ j'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('t$Pf \\$V'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('W?PPUSPQ'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('\\$(X+D$$'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('[BckSp]'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('Remcos'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('CreateObject("WScript.Shell").Run "cmd /c ""'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('t]<*u?N'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('SUVWj7_'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('pth_unenc'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('StopReverse'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('fso.DeleteFolder "'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('while fso.FileExists("'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('GetDirectListeningPort'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('/sort "Visit Time" /stext "'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('wnd_\%04i\%02i\%02i_\%02i\%02i\%02i'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('time_\%04i\%02i\%02i_\%02i\%02i\%02i'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('fso.DeleteFile(Wscript.ScriptFullName)'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('9l$`~A'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('t$LVU3'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('tD;Ntr'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('VjxVVh'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('L$<jHY'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('s u&j@'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('D$$PuJ'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('u79|$$'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('_9l$Lt'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('SVWjGZ'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find(';G,uBSV'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('t%<.t<G'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('^f9t$ s'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('I9t$4t+'))
    if x > -1: logging.info('┝REMCOS')
    if x > -1: Score = Score + 6
    x = (content.find('SYSTEM\\CurrentControlSet\\ControlTerminal Server\\AddIns\\Clip Redirector'))
    if x > -1: logging.info('┝AVE_MARIA')
    if x > -1: Score = Score + 5
    x = (content.find('select signon_realm, origin_url, username_value, password_value from wow_logins'))
    if x > -1: logging.info('┝AVE_MARIA')
    if x > -1: Score = Score + 5
    x = (content.find('Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper'))
    if x > -1: logging.info('┝AVE_MARIA')
    if x > -1: Score = Score + 5
    x = (content.find('A pure virtual function was called. This is a fatal error, and indicates a serious error in the implementation of the application'))
    if x > -1: logging.info('┝AVE_MARIA')
    if x > -1: Score = Score + 5
    x = (content.find('cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q'))
    if x > -1: logging.info('┝AVE_MARIA')
    if x > -1: Score = Score + 5
    x = (content.find('N^RV[\\6yeg'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('jVfc8\\@OeU'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('PqIIi4Zb>4'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('nj)r\\Rx?Jj'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('dt9q9<oDf7'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('8yi"V    Ww|8'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('Ydk{g(B7Hj'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('%\\4*<b"]q2-'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('\%M|+K|K28/,'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('WNPNLNENS.T'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('s\'EtEDW@ts~L'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('51=o>g7RxQj='))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('F* ($,"*&.!)\''))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('_t:lN+XBjRe\' '))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('0\/0?0F0b0s0z0'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    x = (content.find('2 282?2K2Z2u2|2'))
    if x > -1: logging.info('┝BadRabbit')
    if x > -1: Score = Score + 19
    if Score > 69:
        logging.info(f'┕Score: {Score}')
        sys.exit()
    if Score < 69:
        if Score > 20:
            logging.warning(f'┕Score: {Score}')
            sys.exit()
    if Score < 20:
        if Score > 16:
            logging.warning(f'┕Score: {Score}')
            sys.exit()
    if Score < 16:
        if Score > -1:
            logging.info(f'┕Score: {Score}')
    sys.exit()

if __name__ == '__main__':
    if os.path.isfile(''.join(sys.argv[1:])):
        cscan(''.join(sys.argv[1:]))
