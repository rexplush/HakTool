# HakTool
Used to operate very basic works and doing attacksloke
1.Switches between modes of an wireless network interface.
2.Can check the support of packet injection of a wireless adapter.
3.Can change the I.P and M.A.C address of an interface.
4.Can scan the devices on local subnet's.

**Run script by typing "sudo python3 main.py -i {specify interface}" or type "sudo python3 main.py -help" for other commands **

# Command line arguments
1.-i INTERFACE     Used to to specify interface ** it's a mandatory command **.
2.--cip=CIP1       Used to change IP Address of the interface and type Ip Addres to be set.
3.--cmac=CMAC1     Used to change MAC Address of the interface and type MAC Address to be set
4.--mon=MON1       Used to change the mode of interface to monitor and type Y to continue
5.--man=MAN1       Used To change the mode of interface to managed and type Y to continue
6.--pis=PIS1       Used to check packet injection support on interface and type Y to continue
7.--scan=SCAN1     Used to scan devices on locale subnet and type Y to continue
8.--deauth=DEAUTH  Used to run DOS Attack
9.--info=INFO1     Get's you all info and type Y to continue

** You can run it without command line arguments.**
Run program by typing "sudo python3 main.py -i {specify interface}"
Then type "list" or "help" to get a list of commands to run
