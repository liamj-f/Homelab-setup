# Stop all running containers
sudo docker stop $(sudo docker ps -aq) 2>/dev/null || true

# Remove all containers
sudo docker rm $(sudo docker ps -aq) 2>/dev/null || true

# Remove all images
sudo docker rmi $(sudo docker images -q) 2>/dev/null || true

# Remove all volumes
sudo docker volume rm $(sudo docker volume ls -q) 2>/dev/null || true

# Stop Docker service
sudo systemctl stop docker
sudo systemctl stop docker.socket
sudo systemctl disable docker
sudo systemctl disable docker.socket

# Remove Docker packages
sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Remove Docker data directories
sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd
sudo rm -rf /etc/docker
sudo rm -rf ~/.docker

# Remove systemd overrides if you created any
sudo rm -rf /etc/systemd/system/docker.service.d

# Clean up apt
sudo apt-get autoremove -y
sudo apt-get autoclean

# Reload systemd
sudo systemctl daemon-reload
