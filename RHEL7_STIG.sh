#!/bin/bash

# Updates and necessary software for future actions and compliance
yum update -y && yum upgrade -y
yum install wget -y
yum install lsof -y
yum install nano -y
yum install https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_386/amazon-ssm-agent.rpm -y
yum install dracut-fips -y
yum install aide -y
yum install esc pam_pkcs11 authconfig-gtk -y
aide --init   
dracut -f 
auditctl -f2

# Conditional changes to system for STIG compliance
FILE=/etc/cron.allow
if test -f "$FILE"; then
    chown root $FILE
    chgrp root $FILE
else
    touch $FILE
    chown root $FILE
    chgrp root $FILE
fi

if grep -iq FAIL_DELAY /etc/login.defs
then
    sed -i 's/.*FAIL_DELAY.*/FAIL_DELAY 4/' /etc/login.defs
else
    echo "FAIL_DELAY 4" >> /etc/login.defs
fi

if grep -iq PASS_MIN_DAYS /etc/login.defs
then
    sed -i 's/.*PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
else
    echo "PASS_MIN_DAYS 1" >> /etc/login.defs
fi

if grep -iq PASS_MIN_DAYS /etc/login.defs
then
    sed -i 's/.*PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
else
    echo "PASS_MAX_DAYS 60" >> /etc/login.defs
fi

if grep -iq /var/run/faillock /etc/audit/rules.d/audit.rules
then
    sed -i '/\/var\/run\/faillock/d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records when unsuccessful account access events occur
    
    -w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records when unsuccessful account access events occur
    
    -w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq /etc/sudoers /etc/audit/rules.d/audit.rules
then
    sed -i '/\/etc\/sudoers/d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records when successful/unsuccessful attempts to access the \"/etc/sudoers\" file 

    -w /etc/sudoers -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records when successful/unsuccessful attempts to access the \"/etc/sudoers\" file 

    -w /etc/sudoers -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq /etc/sudoers.d/ /etc/audit/rules.d/audit.rules
then
    sed -i '/\/etc\/sudoers.d\//d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records when successful/unsuccessful attempts to access the files in \"/etc/sudoers.d/\" directory. 

    -w /etc/sudoers.d/ -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records when successful/unsuccessful attempts to access the files in \"/etc/sudoers.d/\" directory. 

    -w /etc/sudoers.d/ -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq /etc/group /etc/audit/rules.d/audit.rules
then
    sed -i '/\/etc\/group/d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/group\".
    -w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/group\".
    -w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq /etc/gshadow /etc/audit/rules.d/audit.rules
then
    sed -i '/\/etc\/gshadow/d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/gshadow\".
    -w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/gshadow\".
    -w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq /etc/shadow /etc/audit/rules.d/audit.rules
then
    sed -i '/\/etc\/shadow/d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/shadow\".
    -w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/shadow\".
    -w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq /etc/security/opasswd /etc/audit/rules.d/audit.rules
then
    sed -i '/\/etc\/security\/opasswd/d' /etc/audit/rules.d/audit.rules
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/security/opasswd\".
    -w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
else
    echo "# Generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/security/opasswd\".
    -w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
fi

if grep -iq Banner /etc/ssh/sshd_config
then
    sed -i '/[Bb]anner/d' /etc/ssh/sshd_config
    echo "# Default banner path
    banner /etc/issue" >> /etc/ssh/sshd_config
else 
    echo "# Default banner path
    banner /etc/issue" >> /etc/ssh/sshd_config
fi 

if grep -ip Protocol /etc/ssh/sshd_config
then
    sed -i 's/.*Protocol.*/Protocol 2/g' /etc/ssh/sshd_config
else
    echo "Protocol 2" >> /etc/ssh/sshd_config
fi

FILE=/etc/cron.daily/aide
if test -f "$FILE"; then
    echo "#!/bin/bash
    
    /usr/sbin/aide --check" > $FILE 
else
    touch $FILE
    echo "#!/bin/bash
    
    /usr/sbin/aide --check" > $FILE 
    chmod 744 $FILE
fi


# Edit all text files for STIG compliance
sed -i 's/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/.*PermitUserEnvironment.*/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/.*HostbasedAuthentication.*/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/.*ClientAliveInterval.*/ClientAliveInterval 600/g' /etc/ssh/sshd_config
sed -i 's/.*ClientAliveCount.*/ClientAliveCount 0/g' /etc/ssh/sshd_config
sed -i 's/.*IgnoreRhosts.*/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/.*IgnoreUserKnownHosts.*/IgnoreUserKnownHosts yes/g' /etc/ssh/sshd_config
sed -i 's/.*GSSAPIAuthentication.*/GSSAPIAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/.*KerberosAuthentication.*/KerberosAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/.*StrictModes.*/StrictModes yes/g' /etc/ssh/sshd_config
sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/g' /etc/ssh/sshd_config
sed -i 's/.*Compression.*/Compression no/g' /etc/ssh/sshd_config
sed -i '/Ciphers and keying/a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
sed -i '/Ciphers and keying/a MACs hmac-sha2-256,hmac-sha2-512' /etc/ssh/sshd_config
#sed -i 's/NOPASSWD.*/''/' /etc/sudoers
sed -i 's/INACTIVE.*/INACTIVE=0/g' /etc/default/useradd
sed -i'/^GRUB_CMDLINE_LINUX/ s/"$/ fips=1"/' /etc/default/grub
sed -i '/^-f/ s/1/2/' /etc/audit/rules.d/audit.rules
sed -i 's/.*ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
sed -i 's/.*lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
sed -i 's/.*dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
sed -i 's/.*ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
sed -i 's/.*difok.*/difok = 8/' /etc/security/pwquality.conf
sed -i 's/.*minclass.*/minclass = 4/' /etc/security/pwquality.conf
sed -i 's/.*minlen.*/minlen = 15/' /etc/security/pwquality.conf
sed -i '/^space_left_action/ s/= .*/= email/' /etc/audit/auditd.conf
sed -i '/active/ s/no/yes/g' /etc/audisp/plugins.d/af_unix.conf
sed -i '/nullok/d' /etc/pam.d/system-auth
sed -i '/nullok/d' /etc/pam.d/password-auth
sed -i '/^.*cert_policy/ s/;$/, ocsp_on;/' /etc/pam_pkcs11/pam_pkcs11.conf
sed -i '/password\ \ \ \ required/a password\ \ \ \ required\ \ \ \ \ \ pam_pwquality.so retry=3' /etc/pam.d/system-auth


# Add/edit text and/or files as required for compliance
echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." > /etc/issue

echo "#
# This file controls the configuration of the audit remote 
# logging subsystem, audisp-remote.
#

remote_server = 
port = 60

# the local port is set to port 60 as expected by the default auditd.conf
# configuration
local_port = 60
transport = tcp
mode = immediate
queue_depth = 200
format = managed
network_retry_time = 1
max_tries_per_record = 3
max_time_per_record = 5
heartbeat_timeout = 15

network_failure_action = syslog
disk_low_action = ignore
disk_full_action = syslog
disk_error_action = syslog
remote_ending_action = reconnect
generic_error_action = syslog
generic_warning_action = syslog

enable_krb5 = yes
##krb5_principal =
#krb5_client_name = auditd
##krb5_key_file = /etc/audisp/audisp-remote.key" > /etc/audisp/audisp-remote.conf

echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S execve -C gid!=euid -F euid=0 -k setuid" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "clean_requirements_on_remove=1" >> /etc/yum.conf 
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

# Change configurations of users with shell access
cat /etc/passwd | grep /bin/bash | cut -d: -f 1 > ~/users.txt
cat ~/users.txt | while read USER ; do
    chage -m 1 $USER;
    chage -M 60 $USER;
    done

# Change privilege modes
chmod 0600 /etc/ssh/*key 

# Run commands to update configuration files
grub2-mkconfig -o /boot/grub2/grub.cfg
sysctl --system
