# First 48

### TODO:
<details>
  <summary>Kubernetes</summary>
  <p>I think we should automate a kubebench run to check if we are using best security practices</p>
  <ul>
    <li>YAML:</li>
    https://gitlab.com/nuccdc/tools/-/blob/master/scripts/unix/kubebench/job.yaml?ref_type=heads
    <li> I have started working on a scrip to run the kubebench</li>
  </ul>
</details>



## 1. Clone the repository
```bash
git clone https://github.com/rwu-cyber/cyber-team.git
cd cyber-team
git switch dev-neccdc-2026
```
## 2. Enumeration
#### Run Enumeration Script
May need to run chmod +x _script.sh_ to make executable
```bash
cd linux/scripts
sudo ./enumeration.sh
```
#### Create Backup Admins
```bash
sudo ./createLocalAdmin.sh
```
#### Run AV Scan
```bash
cd ../tools
sudo ./scan.sh
# OR RUN IN BACKGROUND
sudo nohup ./scan.sh & ## output goes to nohup.out and logs/
```
