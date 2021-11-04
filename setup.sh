#!/bin/bash
#Start Functions
#Start User Creation
script_functions="full_run, add_user username, lock_user username, unlock_user username, test_ssh_config, fail_2_ban, harden_ssh, audit_ssh, install_google_auth_ssh, disable_ssh_pass, run_updates, enable_ufw, configure_unattended_upgrades, backup_initiate, add_backup, backup_exclude, backup_snapshot, backup_policy_edit, backup_script_create, backup_script_edit, add_cron_backup"
add_user(){
  adduser "$1";
  echo "attempting to add sudoer";
  usermod -aG sudo "$1";
}
lock_user(){
  echo -e "Disabling $1's User Account";
  usermod -L -e 1 "$1";
  passwd --status "$1";
}
unlock_user(){
  echo -e "Enabling $1's User Account";
  usermod -U -e "" "$1";
  passwd --status "$1"
}
backup_ssh_config(){
  echo -e "Creating backup of sshd_config file labeled $1";
  cp /etc/ssh/sshd_config /etc/ssh/"$1";
}
test_ssh_config(){
  echo "Testing Config File";
  if sshd -t >> ./error.log; then
    echo "Test Successful.";
  else
    echo -e "FAILURE IN FILE!"; tail ./error.log;
  fi
  read -p "If You do NOT want to continue, press CTL-C. Else type 'y'" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      service sshd restart;
  fi
}
fail_2_ban(){
  apt-get install fail2ban;
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local;
  read -p "Please add 'enabled = true' under the [sshd] section of the following file. Proceed? y/n" -n 1 -r;
  echo    # (optional) move to a new line;
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
    #sed -e "/[sshd]/a enabled = true" /etc/fail2ban/jail.local; - THis line does NOT work
    nano /etc/fail2ban/jail.local;
  fi
  service fail2ban restart;
}
harden_ssh(){
  if cat /etc/ssh/sshd_config | grep "#File Hardened by script" > /dev/null
  then
    echo "File already hardened. Aborting."
    exit;
  fi
  #Continue by hardening the SSH file
  backup_ssh_config 'sshd_config.harden_back';
  #cp /etc/ssh/sshd_config /etc/ssh/backup.sshd_config
  echo "Copying Text into the config file";
  echo "#File Hardened by script" >> /etc/ssh/sshd_config;
  echo "Protocol 2" >> /etc/ssh/sshd_config;
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config;
  echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config;
  echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config;
  echo -e "AllowUsers $SUDO_USER" >> /etc/ssh/sshd_config;
  echo "X11Forwarding no" >> /etc/ssh/sshd_config;
  echo "HostKey /etc/ssh/ssh_host_ed25519_key" >> /etc/ssh/sshd_config;
  echo "HostKey /etc/ssh/ssh_host_rsa_key" >> /etc/ssh/sshd_config;
  echo "KexAlgorithms curve25519-sha256@libssh.org" >> /etc/ssh/sshd_config;
  echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config;
  echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config;
  echo "Please use ssh-keygen AND ssh-copy-id $SUDO_USER@$HOSTNAME to add your keys";
  test_ssh_config;
}
audit_ssh(){
  echo "Running SSH audit";
  wget -O audit.py https://raw.githubusercontent.com/arthepsy/ssh-audit/master/ssh-audit.py;
  python audit.py 127.0.0.1;
  sleep 10s;
}
install_google_auth_ssh(){
  backup_ssh_config 'sshd_config.google_auth_back';
  apt-get install libpam-google-authenticator;
  #Run command under user and not root
  sudo -u "$SUDO_USER" google-authenticator;
  if cat /etc/pam.d/sshd | grep "auth required pam_google_authenticator.so" > /dev/null
  then
    echo "PAM file already updated"
  else
    echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/sshd;
  fi
  sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config;
  test_ssh_config;
}
disable_ssh_pass(){
  backup_ssh_config 'sshd_config.disable_pass_back';
  echo "Adding PasswordAuthentication no to the file";
  if cat /etc/ssh/sshd_config | grep "PasswordAuthentication no" > /dev/null
  then
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config;
    test_ssh_config;
  else
    echo "SSH Password auth already disabled"
  fi
}

run_updates(){
  # Update Host
  echo "Running Updates";
  apt-get update;
  apt-get upgrade -y;
  echo "updates completed";
}
enable_ufw(){
  apt-get install ufw
  ufw default deny incoming;
  ufw default allow outgoing;
  ufw allow ssh;
  ufw app list;
  read -p "Would you like to add another service/port besides ssh? y/n" -n 1 -r;
  echo    ;# (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      read ufw_service;
      ufw allow "${ufw_service}";
  fi
  ufw show added;
  read -p "Do you want to enable UFW?" -n 1 -r;
  echo    ;# (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      ufw enable;
      echo "UFW is now enabled";
      ufw status verbose;
      sleep 5;
  fi
}
configure_unattended_upgrades(){
  echo "Checking the install of the package";
  apt-get install unattended-upgrades apt-listchanges
  dpkg-reconfigure unattended-upgrades
  echo "completed unattended upgrades"
}
backup_snapshot(){
  echo "#"
  echo "# Listing advailable snapshots #"
  kopia snapshot ls
  echo "#"
  echo "#"
  read -p "Enter the path to snapshot" snap
  kopia snapshot $snap
}
backup_exclude(){
  read -p "Enter the additional name to exclude" exclude
  kopia policy set --global --add-ignore exclude
}
backup_policy_edit(){
  kopia policy edit global
}
backup_script_create(){
  echo "#!/bin/bash" > /backup/before.sh
  echo "#!/bin/bash" > /backup/after.sh
  read -p "Add Healthchecks.io URL?" -n 1 -r;
  echo    ;# (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      read -p "Enter the URL for healthchecks.io" healthCheck
      echo -e "wget ${healthCheck}/start > /dev/null" >> backup/before.sh
      echo -e "wget ${healthCheck} > /dev/null" >> backup/after.sh
  fi
  chmod 500 /backup/before.sh
  chmod 500 /backup/after.sh
}
backup_script_edit(){
  read -p "Do you want to edit the before script?" -n 1 -r;
  echo    ;# (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      chmod 700 /backup/before.sh
      nano /backup/before.sh
      chmod 500 /backup/before.sh
  fi
  read -p "Do you want to edit the after script?" -n 1 -r;
  echo    ;# (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      chmod 700 /backup/after.sh
      nano /backup/after.sh
      chmod 500 /backup/after.sh
  fi
}
add_cron_backup(){
  echo "This funciton will attempt to guide the user through adding/editing the crontab. Please screenshot or save these steps if you havn't done this before."
  echo "Follow the steps exactly"
  echo "1. Open the following: https://crontab-generator.org/"
  echo "2. Edit the run-time seting to your desire"
  echo "3. In the 'Command To Execute' section, paste '/backup/before.sh && kopia snapshot --all && /backup/after.sh'"
  echo "4. Add any output handling options. Aka write to /backup/log.txt"
  echo "5. Click Generate Crontab Line"
  echo "6. Copy the generated crontab line and paste it into editor (when opened)"
  echo "7. Save the file"
  read -p "Are you ready to begin?" -n 1 -r;
  echo    ;# (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      crontab -e
  fi
  echo "Validation output:"
  crontab -l
  echo "##### IF THE VALIDATION FAILED, YOU MUST RE-EDIT THE FILE! #####"
}
backup_initiate(){
  apt-get install rclone
  echo "Running the rclone config script"
  rclone config
  echo "Creating backup directory for backup scripts at /backup"
  mkdir /backup
  echo "Installing Kopia"
  echo "dev http://packages.kopia.io/apt/ stable main" | tee /etc/apt/sources.list.d/kopia.list
  apt update
  apt install kopia
  echo "Setting up compression"
  kopia policy set --global --compression=zstd
  kopia policy set --global \
  --add-never-compress ".zip" \
  --add-never-compress ".ZIP" \
  --add-never-compress ".7z" \
  --add-never-compress ".7Z" \
  --add-never-compress ".rar" \
  --add-never-compress ".RAR" \
  --add-never-compress ".pdf" \
  --add-never-compress ".PDF" \
  --add-never-compress ".png" \
  --add-never-compress ".PNG" \
  --add-never-compress ".jpg" \
  --add-never-compress ".JPG" \
  --add-never-compress ".jpeg" \
  --add-never-compress ".JPEG" \
  --add-never-compress ".webp" \
  --add-never-compress ".WEBP" \
  --add-never-compress ".avi" \
  --add-never-compress ".AVI" \
  --add-never-compress ".mp3" \
  --add-never-compress ".MP3" \
  --add-never-compress ".mp4" \
  --add-never-compress ".MP4" \
  --add-never-compress ".mkv" \
  --add-never-compress ".MKV" \
  --add-never-compress ".ogg" \
  --add-never-compress ".OGG" \
  --add-never-compress ".opus" \
  --add-never-compress ".OPUS" \
  --add-never-compress ".gif" \
  --add-never-compress ".GIF"
  echo "Setting exclusions of tmp, cache, node_modules, .git"
  kopia policy set --global \
  --add-ignore "tmp" \
  --add-ignore "cache" \
  --add-ignore "node_modules" \
  --add-ignore ".git"
  read -p "Do you need to configure additional exclusions? y/n" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
    backup_exclude
  fi
  echo "Additional exclusions can be added through the backup_exclude function or kopia policy set --global --add-ignore 'name'"
  read -p "Would you like to add an snapshot? Remember, this will ONLY backup specified directories y/n" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
    backup_snapshot
  fi
  echo "Immediate snapshots can be added through the function backup_snapshot and kopia snapshot PATH"
  read -p "Would you like to change the default policy settings? y/n" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
    backup_policy_edit
  fi
  echo "This policy can be configured with ./setup.sh backup_policy_edit OR kopia policy edit global"
}
restore_backup(){
  echo "See https://kopia.io/docs/mounting/"
  echo "This script will NOT do the restore for you."
}
add_backup(){
  echo ""
  echo "NOTE: This script assumes nothing is currently configured. Use backup_snapshot to create a new directory if already configured"
  echo ""
  read -p "Do you need to configure rclone and install kopia? y/n" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      backup_initiate
  fi
  echo "Starting Kopia Configuration"
  echo "Using setup listed at https://ftlwebservices.com/2021/10/fast-and-reliable-automated-cloud-backups-with-kopia-and-backblaze/"
  echo "And https://kopia.io/docs/repositories/#rclone"
  echo "#"
  echo "#"
  echo "#"
  echo "#"
  rclone listremotes
  echo "#"
  echo "#"
  echo "Please copy the full remote name from the above list. You will need it for the template AND the rclone script"
  echo "Be ready with the previous encryption paraphrase."
  #echo "Know the PATHs you want to backup and any supporting scripts (powering down docker containers, stoping services, etc)"
  #echo "If you want to enable healthchecks, goto https://healthchecks.io/ and generate the URL"
  read -p "Are you ready to start? y/n" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Nn]$ ]]
  then
      echo "Backup failed. Please run 'sudo ./setup.sh add_backup' again"
      exit
  fi
  echo ""
  read -p "Please enter the rclone name:" rPath
  echo -e "This will configure backups at ${rPath}/backups/$HOSTNAME"
  kopia repository create rclone --remote-path "$rPath/backups/$HOSTNAME"
  echo "Running validation"
  kopia repository connect rclone --remote-path "$rPath/backups/$HOSTNAME"
  read -p "If validation was Successful, did you want to add the CRON job to automatically run it? y/n" -n 1 -r;
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
    backup_script_create
    backup_script_edit
    add_cron_backup
  fi

}

#Start Script
full_run(){
  echo "This script requires sudo access. I made this script, so please know what your doing )";
  if [ "$EUID" -ne 0 ]
    then
    echo "Please run with sudo";
    exit;
  fi
  run_updates
  # Start User Pi Identification
  #echo $SUDO_USER
  if [[ $SUDO_USER = "pi" ]]
  then
    echo "Please Enter a LOWERCASE username for the new user as pi is not recommended";
    read user;
    read -p "Is ${user} Correct?" -n 1 -r;
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        add_user "${user}";
    fi
    echo -e "Please re-run script as new user ${user}. Note, if you are in a SSH session, rejoin under the new user.";
    exit;
  else
    #Make sure the pi account is locked
    if cat /etc/passwd | grep 'pi:' > /dev/null; then
      #statements
      read -p "Would you like to disable the pi user? (might already be disabled) y/n" -n 1 -r;
      echo    # (optional) move to a new line
      if [[ $REPLY =~ ^[Yy]$ ]]
      then
          lock_user 'pi';
      fi
    fi
    #Ask to lock root - DISABLED DUE TO CONFLICTS WITH GOOGLE AUTH.
    #read -p "Would you like to lock the root account at this time? y/n" -n 1 -r;
    #echo    # (optional) move to a new line
    #if [[ $REPLY =~ ^[Yy]$ ]]
    #then
    #    lock_user 'root';
    #fi
    #Start Hardening sshd.config file
    read -p "Would you like to harden the sshd_config file at this time? y/n" -n 1 -r;
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        harden_ssh;
    fi
    #Start disable password login or 2FA
    read -p "Would you like to disable password logins now? This will not take effect until the service is reloaded. y/n" -n 1 -r;
    echo    # (optional) move to a new line
    #Ask for disabling password auth
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
      disable_ssh_pass;
    else
      read -p "Would you like to install and enable google authenticator? y/n" -n 1 -r
      echo    # (optional) move to a new line
      if [[ $REPLY =~ ^[Yy]$ ]]
      then
        install_google_auth_ssh;
      fi
    fi
    test_ssh_config;
    #Fail to ban
    read -p "Would you like to setup and configure Fail2Ban? y/n" -n 1 -r
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        fail_2_ban;
    fi
    #Audit SSH
    read -p "Would you like to audit SSH configuration? y/n" -n 1 -r
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        audit_ssh;
    fi
    #Enable UFW
    read -p "Would you like to enable UFW now? SSH will be enabled by default. Do NOT USE FOR DOCKER HOST y/n" -n 1 -r;
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        enable_ufw;
    fi
    echo "Hardening Completed.";
    #Enable UFW
    read -p "Would you like to add backups now? y/n" -n 1 -r;
    echo    # (optional) move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        add_backup;
    fi
    echo "Backups Completed.";
  fi
  echo -e "Script finished Full Run. Individual functions can be called with './setup.sh FUNCTION_NAME'. Advailable functions: ${script_functions}"
}
#End Full run
echo -e "Call script with 'sudo ./setup.sh full_run' with sudo or choose of the following functions: ${script_functions}";
"$@";
