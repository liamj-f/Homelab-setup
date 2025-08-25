# rpi4-docker

This repo is for Liams Raspberry Pi4 8gb docker compose files


Using the router usb:

/etc/fstab has been editted to create the mount point for the routers smb H drive, but then commented out as systemd now handles this  
/etc/systemd/system/mnt-NextCloudTest.mount also created #prevents mounting before router is ready if the pi reboots  
/etc/systemd/system/mnt-NextCloudTest.automount also created #remounts drive if router reboots  

This is the systemd daemon service that handles the mounting/unmounting
sudo systemctl daemon-reload  
sudo systemctl enable mnt-NextCloud.automount  
sudo systemctl start mnt-NextCloud.automount  
