
## About the Bootstrap
The bootstrap file contains most of the current blockchain data in a downloadable zip file. You can use this data with your **Infinity Node** or **local wallet** to quickly sync. This method is much faster because you do not need to download every block over the p2p node network, which can take many hours or days depending on internet speed.

## Windows Bootstrap

To quickly re-sync your local Windows wallet follow the steps below:

- Download the latest bootstrap archive available:
https://bootstrap.sinovate.io/index.php/s/Y9T2JR3ZiiqDIWl/download
- If open, close the wallet
- Go to your local SIN folder located at `%appdata%\SIN\`
	- (This defaults to `C:\Documents and Settings\YourUserName\Application data\SIN\` on Windows XP and to `C:\Users\YourUserName\Appdata\Roaming\SIN\` on Windows Vista, 7, 8, and 10.)
- Delete `blocks`,`chainstate` and indexes folders.
- Unzip the downloaded `bootstrap.zip` file
- Move the `blocks`, `chainstate`, indexes folders and infinitynode dat files inside the SIN folder at `%appdata%\SIN\`
- Open the local wallet again.

## Linux CLI Bootstrap

:warning: You must log in with the user you created during installation.

In case you need to quickly sync the blockchain of your Infinity Node or linux wallet, follow the commented steps below:

```bash

# Disable it if you are using a crontab
crontab -l > my_cron_backup.txt
crontab -r

# If running Infinity Node, stop it.
sudo systemctl stop sinovate.service
./sin-cli stop

# install unzip package
sudo apt update && sudo apt install unzip

# remove old files and folders
rm -rf ~/.sin/{blocks,chainstate,indexes,debug.log,mnpayments.dat,mncache.dat,banlist.dat,peers.dat,netfulfilled.dat,governance.dat,fee_estimates.dat}

# download latest bootstrap archive
curl -J -O https://bootstrap.sinovate.io/index.php/s/Y9T2JR3ZiiqDIWl/download

# unzip the bootstrap archive
unzip ~/bootstrap.zip

# move bootstrap files
mv -ft ~/.sin ~/bootstrap/blocks ~/bootstrap/chainstate ~/bootstrap/indexes ~/bootstrap/infinitynode*.dat

# remove unnecessary files
rm -rf ~/{bootstrap,bootstrap.zip}

# To restore crontab

crontab my_cron_backup.txt
crontab -l

# reboot infinitynode
sudo reboot
```
