#!/bin/bash
#!/bin/sh

banner() {
clear
printf " ████████╗ █████╗ ██╗██╗      ██████╗  █████╗ ████████╗███████╗ \n"
printf "╚══██╔══╝██╔══██╗██║██║     ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝ \n"
printf "   ██║   ███████║██║██║     ██║  ███╗███████║   ██║   █████╗   \n"
printf "   ██║   ██╔══██║██║██║     ██║   ██║██╔══██║   ██║   ██╔══╝   \n"
printf "   ██║   ██║  ██║██║███████╗╚██████╔╝██║  ██║   ██║   ███████╗ \n"
printf "   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ \n"
                                                              
                                                              
                                                                                                              
                                                              
                                                         
printf "\n"
}
menu() {
printf "\e[1;92m[\e[0m\e[1;77m01\e[0m\e[1;92m]\e[0m\e[1;93m Start Capturing\e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m02\e[0m\e[1;92m]\e[0m\e[1;93m Open the Captured file\e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m03\e[0m\e[1;92m]\e[0m\e[1;93m Analysis\e[0m\n"

printf "\n"
printf "\e[1;93m[\e[0m\e[1;77m99\e[0m\e[1;93m]\e[0m\e[1;77m Exit\e[0m\n"
printf "\n"
read -p $'\e[1;92m[*] Choose an option:\e[0m\e[1;77m ' option

if [[ $option == 1 || $option == 01 ]]; then
gcc packet.c -lpcap -o capture
sudo ./capture

elif [[ $option == 2 || $option == 02 ]]; then
cat sniffed.txt

elif [[ $option == 3 || $option == 03 ]]; then

bash a.sh 

elif [[ $option  == 99 ]]; then
exit 1
else
printf "\e[5;93m[\e[1;77m!\e[0m\e[1;93m] Invalid option!\e[0m"
sleep 0.5
clear
banner
menu
fi
}
banner
menu
		
