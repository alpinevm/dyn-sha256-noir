sudo apt update
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get install git-lfs
git lfs install
git clone https://github.com/alpinevm/dyn-sha256-noir
cd dyn-sha256-noir
sudo DEBIAN_FRONTEND=noninteractive apt install -y python3-pip
python3 -m pip install aiofiles
python3 -m pip install psutil
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
source /home/ubuntu/.bashrc
noirup --version v0.26.0
sudo cp ./cached_bb/bb /usr/bin/
echo "startup_message off" >> ~/.screenrc
screen
python3 scripts/generate_circuits.py
