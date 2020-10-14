#!/bin/bash
#!/bin/sh

banner() {
clear
printf " █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗ \n"
printf "██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝ \n"
printf "███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗ \n"
printf "██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║ \n"
printf "██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║ \n"
printf "╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝ \n"
                                                                         
                                                                                                              
                                                              
                                                         
printf "\n"
}
menu() {

printf "\e[1;92m[\e[0m\e[1;77m01\e[0m\e[1;92m]\e[0m\e[1;93m To see ETHERNET-HEADER\e[0m\n"

printf "\e[1;92m[\e[0m\e[1;77m02\e[0m\e[1;92m]\e[0m\e[1;93m To see IP HEADER\e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m03\e[0m\e[1;92m]\e[0m\e[1;93m To see all TCP packets\e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m04\e[0m\e[1;92m]\e[0m\e[1;93m To see all UDP packets \e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m05\e[0m\e[1;92m]\e[0m\e[1;93m To see all ICMP packets\e[0m\n"

printf "\e[1;92m[\e[0m\e[1;77m06\e[0m\e[1;92m]\e[0m\e[1;93m To see all IGMP packets\e[0m\n"

printf "\e[1;92m[\e[0m\e[1;77m07\e[0m\e[1;92m]\e[0m\e[1;93m To see all MISC packets\e[0m\n"
printf "\n"
printf "\e[1;93m[\e[0m\e[1;77m99\e[0m\e[1;93m]\e[0m\e[1;77m Exit\e[0m\n"
printf "\n"
read -p $'\e[1;92m[*] Choose an option:\e[0m\e[1;77m ' option

if [[ $option == 1 || $option == 01 ]]; then

awk '$0 == "Ethernet Header" {i=1;next};i && i++ <= 18' sniffed.txt
elif [[ $option == 2 || $option == 02 ]]; then

awk '$0 == "IP Header" {i=0;next};i && i++ <= 18' sniffed.txt

elif [[ $option == 3 || $option == 03 ]]; then
awk '$0 == "***********************TCP Packet*************************" {i=1;next};i && i++ <= 18' sniffed.txt

elif [[ $option == 4 || $option == 04 ]]; then
awk '$0 == "***********************UDP Packet*************************" {i=1;next};i && i++ <= 18' sniffed.txt

elif [[ $option == 5 || $option == 05 ]]; then
awk '$0 == "***********************UDP Packet*************************" {i=1;next};i && i++ <= 18' sniffed.txt

elif [[ $option == 6 || $option == 06 ]]; then
awk '$0 == "***********************ICMP Packet*************************" {i=1;next};i && i++ <= 18' sniffed.txt

elif [[ $option == 7 || $option == 07 ]]; then
awk '$0 == "***********************IGMP Packet*************************" {i=1;next};i && i++ <= 18' sniffed.txt

elif [[ $option == 3 || $option == 03 ]]; then
awk '$0 == "***********************TCP Packet*************************" {i=1;next};i && i++ <= 18' sniffed.txt
 

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
		
