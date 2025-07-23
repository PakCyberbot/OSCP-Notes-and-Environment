#!/bin/bash

# Define colors
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

# Display banner
echo -e "${RED}"

cat <<'EOF'
   ____  _____ __________ 
  / __ \/ ___// ____/ __ \
 / / / /\__ \/ /   / /_/ /
/ /_/ /___/ / /___/ ____/ 
\____//____/\____/_/      
                          
    _______   ___    __________  ____  _   ____  __________   ________
   / ____/ | / / |  / /  _/ __ \/ __ \/ | / /  |/  / ____/ | / /_  __/
  / __/ /  |/ /| | / // // /_/ / / / /  |/ / /|_/ / __/ /  |/ / / /   
 / /___/ /|  / | |/ // // _, _/ /_/ / /|  / /  / / /___/ /|  / / /    
/_____/_/ |_/  |___/___/_/ |_|\____/_/ |_/_/  /_/_____/_/ |_/ /_/     

EOF
echo -e "${NC}"

# Intro message
echo -e "${CYAN}${BOLD}🏴 OSCP Environment Setup${NC}"
echo -e "Created by ${YELLOW}pakcyberbot${NC} – To support ${CYAN}https://buymeacoffee.com/pakcyberbot${NC}\n"

# Feature list
echo -e "${GREEN}FEATURES:${NC}"
echo -e "  • ${BOLD}Multi‑terminal${NC} quick setup for different environments"
echo -e "  • ${BOLD}Markdown templates${NC} for notes & reporting"
echo -e "  • ${BOLD}Enhanced Markdown → PDF generator${NC}"
echo -e "  • ${BOLD}Terminal logging${NC} of sessions"
echo -e "  • ${BOLD}Fuzzy HTTP server${NC} (typo correction, file upload, deliverable binaries)"

echo

read -s -p "Enter your password: " password

echo ''


sudo -v -S <<< "$password"
 
# Don't run it with root just need password for installing binaries
if [ "$(id -u)" -eq 0 ]; then   
    echo "This script should not be run as root."
    exit 1
fi

dos2unix .myterm_settings

# Check the bash/zsh environment settings
cp .myterm_settings "$HOME/"

current_shell=$(basename "$SHELL")
config_file="$HOME/.$current_shell"rc

if grep -q "source $HOME/.myterm_settings" "$config_file"; then
    echo "No need to make changes in $config_file"
else
    echo "source $HOME/.myterm_settings" >> $config_file
fi
source "$HOME/.myterm_settings"


# Create missing directories
if [ ! -d "$HOME/ACTIVE_PENTEST" ]; then
    mkdir "$HOME/ACTIVE_PENTEST"
fi


dos2unix setup_pentest_env
dos2unix md2pdf_reportgen
dos2unix toggle-terminal-logging

# Copying all the binaries to /usr/local/bin
echo "[+] Copying binaries to /usr/local/bin..."

sudo cp setup_pentest_env "/usr/local/bin/setup_pentest_env"
sudo chmod +x "/usr/local/bin/setup_pentest_env"

sudo cp md2pdf_reportgen "/usr/local/bin/md2pdf_reportgen"
sudo chmod +x "/usr/local/bin/md2pdf_reportgen"

sudo cp toggle-terminal-logging "/usr/local/bin/toggle-terminal-logging"
sudo chmod +x "/usr/local/bin/toggle-terminal-logging"  

echo -e "${GREEN}✅ Binaries copied to /usr/local/bin${NC}"

# Fuzzy http server will gonna implement this later
# if [ ! -w "/opt" ]; then
#     echo "You don't have permission to write on $directory"
#     sudo chmod o+w /opt
# else
#     echo "You have permission to access $directory"
# fi

# if [ ! -d "/opt/transfers" ]; then
#     mkdir "/opt/transfers"
# fi
# cp -r transfers "/opt/transfers"

# if [ ! -d "/opt/bin" ]; then
#     mkdir "/opt/bin"
# fi


# Checks if required binaries installed
if command -v terminator &> /dev/null; then
    echo "Terminator installed already."
else
    echo "[+] Installing Terminator Now..."
    sudo apt install terminator
fi

if [ ! -d "/home/kali/.config/terminator/" ]; then
    mkdir -p "/home/kali/.config/terminator/"
fi

cp terminator_config "$HOME/.config/terminator/config"


echo "[+] Installing fuzzy-httpserver"
echo -e "${GREEN}✅ fuzzy-httpserver installed${NC}"



# Display setup completion message
echo -e "${GREEN}${BOLD}✔ Setup Completed Successfully!${NC}\n"

echo -e "${CYAN}${BOLD}🚀 Available Commands:${NC}"

echo -e "  ${YELLOW}- setup_pentest_env${NC}"
echo -e "    Launch multiple terminal windows with appropriate environment variables."
echo -e "    Supports OSCP exam-style layout as well."
echo -e "    🎥 Demo: ${MAGENTA}PakCyberbot's GitHub${NC}\n"

echo -e "  ${YELLOW}- md2pdf_reportgen${NC}"
echo -e "    Convert your Obsidian Markdown notes to polished PDFs."
echo -e "    Adds image captions, borders, and preserves consistent formatting.\n"

echo -e "  ${YELLOW}- toggle-terminal-logging${NC}"
echo -e "    Toggle full terminal session logging (including reverse shells)."
echo -e "    🔎 Essential for reviewing commands during report writing.\n"

echo -e "  ${YELLOW}- fuzzy-httpserver${NC}"
echo -e "    Start a smart HTTP file server from the current directory."
echo -e "    ✨ Features:"
echo -e "      • Auto-corrects typos in URLs"
echo -e "      • Recieves file uploads"
echo -e "      • Preloaded with common pentest binaries\n"

echo -e "  ${YELLOW}- bloodhound-docker start${NC} / ${YELLOW}stop${NC}"
echo -e "    Spin up or stop BloodHound in seconds using Docker."
echo -e "    Configs are pre-written in ${BOLD}~/.myterm_settings${NC}\n"

echo -e "${CYAN}${BOLD}📝 Obsidian Markdown Templates:${NC}"
echo -e "  Includes exam note-taking and report templates for Obsidian."
echo -e "  Works with the Templater plugin to dynamically insert IPs and content."
echo -e "  📦 ${MAGENTA}PakCyberbot will soon share his full Obsidian vault with preconfigured plugins.${NC}\n"

echo -e "${CYAN}${BOLD}🎛️ Terminator Keyboard Shortcuts:${NC}"
echo -e "  ${YELLOW}• Ctrl+Shift+L${NC} → Vertical split"
echo -e "  ${YELLOW}• Ctrl+Shift+J${NC} → Horizontal split"
echo -e "  ${YELLOW}• Ctrl+Shift+Z${NC} → Zoom in/out of selected terminal"
echo -e "  ${YELLOW}• Ctrl+Shift+W${NC} → Close the current terminal"
echo -e "  ${YELLOW}• Ctrl+Tab${NC}       → Switch between terminals in a window"
echo -e "  ${YELLOW}• Ctrl+N${NC}         → Switch to white theme (great for report screenshots)\n"

echo -e "${CYAN}${BOLD}📣 Feedback & Support:${NC}"
echo -e "  Explore the tools, suggest improvements, or report bugs."
echo -e "  ☕ Support the project: ${MAGENTA}Buy me a coffee — thank you!${NC} : https://buymeacoffee.com/pakcyberbot\n"
