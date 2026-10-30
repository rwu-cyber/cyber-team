# First 48

# TODO:

- [ ] Incorporate some sort of file integrity checker: debsums, tripwire
- [ ] Rootkit checker: chkroot, rkhunter
- [ ] Create a backup directory for important stuff
- [ ] File monitoring with wazuh or other system? Send alerts to soc if important files are changed.
- [ ] Telnet / netcat removal (?)
- [ ] Automate kubebench run to check for best security practices

# 1. Clone the repository

<!-- what if the host doesnt have git for some reason? -->
```bash
git clone https://github.com/rwu-cyber/cyber-team.git && cd cyber-team && git switch dev-neccdc-2027
# Make all scripts executable, or run scripts with interpreter (`bash ./script.sh`)
chmod +x linux/scripts/*
```

# 2. Enumeration
<!-- what if we used ansible playbooks to automate these tasks? -->

## Run Enumeration Script

```bash
cd linux/scripts
sudo ./enumeration.sh
```

## Create Backup Admins

```bash
sudo ./createLocalAdmin.sh
```

## Run AV Scan

```bash
cd ../tools
sudo ./scan.sh
# OR RUN IN BACKGROUND
sudo nohup ./scan.sh & ## output goes to nohup.out and logs/
```
