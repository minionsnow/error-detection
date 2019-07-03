import telnetlib
import time
import re
import argparse
import sys
from data_file import RSPs
from datetime import datetime


################################################################

        #Initilization of the initial parameters like the
        #hostname,console,username,password.

################################################################
parser=argparse.ArgumentParser()
parser.add_argument('-i','--ip',help='router ip')
parser.add_argument('-c','--con',help='router console')
parser.add_argument('-u','--user',help='router username')
parser.add_argument('-p','--pasw',help='router password')
args = parser.parse_args()

if args.ip==None:
	print('No router ip provided : Required information') 
	sys.exit()
if args.con==None:
	print('No router console provided : Required information') 
	sys.exit()
if args.user==None:
	print('No username provided : Taking default(root)')
	args.user='root'
if args.pasw==None:
	print('No password provided : Taking default(lab123)')
	args.pasw='lab123'

host=args.ip
console=args.con
username=args.user
password=args.pasw

################################################################

        #We first enter the our host using the Telnet library
        #and the parameters given above.

        #We have used 'terminal length 0' to avoid any -More-
        #and to get the whole output.

        #'\n' works as an 'Enter'.

        # Sleep time is provided time to time to give time for
        #the commands to run.

        #As the arguments of .read() and .write() need to be
        #bytes rather than string needs to be encoded in Windows

################################################################

timeout=3
tn=telnetlib.Telnet(host,console)
time.sleep(1)   
tn.write('\n'.encode('utf-8'))  
out=tn.read_until('Username:'.encode('utf-8'),timeout)
tn.write((username+'\n').encode('utf-8'))
out=tn.read_until('Password:'.encode('utf-8'),timeout)
tn.write((password+'\n').encode('utf-8'))
time.sleep(1)
tn.write(('terminal length 0\n').encode('utf-8'))
tn.write('\n'.encode('utf-8'))
Summary=[]
TestCases=[]
Summary.append('\n\nSummary:\n\n')

################################################################

        #Functions to be used throughout the script

################################################################

def wrcom(comm,sltime):	#general write function to console
        tn.write((comm+'\n').encode('utf-8'))
        time.sleep(sltime)

def parse(comm,sltime):	#general function to parse the output of the command
        wrcom(comm,sltime)
        out=tn.read_very_eager().decode('utf-8')
	#print(out)
        return out.splitlines()

def admin():	#default function to enter admin
        wrcom('admin',2)

def exit():	#default function to exit
        wrcom('exit',1)

def activersp():	#function to get the current activeRSP in the system
        out1=parse('show platform',2)
        for i in range (len(out1)):
        	match=re.search('Active',out1[i])
        	if match:
        		return out1[i][5]

def ping_ip(ip,a):	#function to ping ip from xr or calvados 
        l=['ping '+ip+' count 2','chvrf 0 ping '+ip+' -c 2']
        l1=['Success rate is 100 percent',', 0% packet loss']
        wrcom(l[a],6)
        out_ping_shell=tn.read_very_eager().decode('utf-8')
        #print(out_ping_shell)
        match=re.search(l1[a],out_ping_shell)
        if match:
        	return 1
        else:
        	return 0

def get_ip(ip_type):	#getting management or default gateway ip from nvram_dump
        admin()
        wrcom('run bash -l',1)
        out_nvram=parse('nvram_dump -r '+ip_type,2)
        for i in range (len(out_nvram)):
        	match=re.search('data is',out_nvram[i])
        	if match :
        		out_nvram_1=out_nvram[i].split()
        		exit()
        		exit()
        		return out_nvram_1[-1]
        	elif i==len(out_nvram)-1:
        		exit()
        		exit()
        		return None

def mgmt_up(activeRSP):	#setting up management ip
        exit()
        if ping_ip('202.153.144.25',0):
        	admin()
        	return 
        else:
        	print("ping unsuccessful") 
        	if get_ip('IP_ADDRESS')!=None:
        		ip_router=get_ip('IP_ADDRESS')
        		print('\tSuccesfully taken mgmt ip')
        		wrcom('con t',1)
        		wrcom('interface mgmtEth 0/RSP'+activeRSP+'/CPU0/0 ',1)
        		wrcom('ipv4 address '+ip_router+'/16',1)
        		wrcom('no shutdown',1)
        		wrcom('commit',1)
        		exit()
        		exit()
        		admin()
        	else:
        		Summary.append('mgmt port down, no mgmt ip')
        		admin()
        #out=tn.read_very_eager().decode('utf-8')
        #print(out)

def gateway_up():	#setting up default gateway ip
        exit()
        if ping_ip('202.153.144.25',0):
                admin()
                return 
        else:
                print("ping unsuccessful") 
                if get_ip('DEFAULT_GATEWAY')!=None:
                        def_gateway=get_ip('DEFAULT_GATEWAY')
                        print('\tSuccesfully taken Gateway ip')
                        wrcom('con t',1)
                        wrcom('router static address-family ipv4 unicast',1)
                        wrcom('0.0.0.0/0 '+def_gateway,1)
                        wrcom('commit',1)
                        exit()
                        exit()
                        exit()
                        admin()
                else:
                        Summary.append('mgmt port down,no gateway ip')

        #out=tn.read_very_eager().decode('utf-8')
        #print(out)
		

def trace(err_name,ip):	#function to save trace in the desired location in case of error
        strtime=time.asctime( time.localtime(time.time()) )
        strtime=strtime.replace(' ','_')
        strtime=strtime.replace(':','-')
        wrcom('run bash -l',1)
        wrcom('cd /opt/cisco/calvados/bin/',1)
        wrcom('./ctracedec -gtAk esd > '+err_name+strtime,3)
        wrcom('cp '+err_name+strtime+' /misc/disk1/',1)
        wrcom('cd',1)
        wrcom('chvrf 0 scp /misc/disk1/'+err_name+strtime+' root@'+ip+':/disk0\:',2)
        exit()
        exit()
        wrcom('copy disk0:/'+err_name+strtime+' tftp://202.153.144.25/auto/tftp-blr-users1/ypandit/traces/'+err_name+strtime,1)
        wrcom('\n',5)
        wrcom('run',1)
        wrcom('rm '+err_name+strtime,1)
        exit()
        admin()
        out=tn.read_very_eager().decode('utf-8')
        print(out)

def c2_sear_err(err_type,out_1):	#function for case to for searching type of error if drops occur
        match1=re.search(err_type,out_1)
        if match1:
                out_2=out_1.split()
                if out_2[-1]!='0':
                        Summary.append('\t'+err_type+'\n')

def c2_board_parse(board_con,out_1):	#function for case 2 to find the drops in EOBC links
        for k in range (len(out_1)):
                match=re.search(RSPs[j]['connection'],out_1[k])
                if match:
                        out_2=out_1[k].split()
                        port=out_2[0]
                        flag_tx=0
                        flag_rx=0
                        if out_2[1]!='Up':
                                Summary.append(board_con+'is not Up')
                        else:
                                if out_2[5]!='0':
                                        Summary.append('Tx drop in '+board_con+' : Reason : \n')
                                        TestCases.append(2)
                                        flag_tx=1
                                if out_2[6]!='0':
                                        Summary.append('Rx drop in '+board_con+' : Reason : \n')
                                        TestCases.append(2)
                                        flag_rx=1
                                if flag_tx!=0 or flag_rx!=0:
                                        command4="show controller switch statistics detail location 0/RP"+rsps[i][0][5]+"/RP-SW "+port
                                        out_stat_det_1=parse(command4,3)	#getting possible reasons (generally) for the drop
                                        for l in range (len(out_stat_det_1)):
                                                c2_sear_err('Rx Errors',out_stat_det_1[l])
                                                c2_sear_err('Rx Bad CRC',out_stat_det_1[l])
                                                c2_sear_err('Rx Policing Drops',out_stat_det_1[l])
                        if flag_tx==0 and flag_rx==0:
                                Summary.append('no drop in '+board_con+' For '+rsps[i][0]+'\n')

def sear_err(type_err,type_vm,out_1):	#function for case 4  to parse for errors in VFs 
        match1=re.search(type_err,out_1)
        if match1:
                match2=re.search(type_err+':0',out_1)
                if match2==None:
                        Summary.append('\t'+type_err+' in '+type_vm+'\n')
                        TestCases.append(4)
                        return 1
        else:
                Summary.append('\t'+type_err+' is nor present in '+type_vm+'\n')
                TestCases.append(4)
                return 1

def sear_drop(x,p_colour,b_type,out_1,p_num):	# function for case 5 to errors in vlans
        match2=re.search(x,out_1)
        if match2==None:
                Summary.append('error in '+p_colour+'_port '+p_num+' in '+b_type+'\n')
                TestCases.append(5)
                return 1
            
def sear_ptype(p_colour,p_type,b_type,out_1):	# function for case 5 to parse the vlans commands output for different ports
        for l in range (len(p_type)):
                match1=re.search(p_type[l],out_1)
                if match1:
                        if (activeRSP=='0' and p_colour=='red') or (activeRSP=='1' and p_colour== 'blue'):
                                return sear_drop('Drop',p_colour,b_type,out_1,p_type[l])
                        elif (activeRSP=='0' and p_colour== 'blue') or (activeRSP=='1' and p_colour== 'red'):
                                return sear_drop('Translate',p_colour,b_type,out_1,p_type[l])

################################################################

        #The command 'show platform' is used to find the active 
        #RSP , we then move to the admin for further processing.

        #The command 'show platform' in the admin gives the
        #operational card so that they can be saved into an
        #array to be used further.

        #We take the output and save it as a string.

        #The string is then converted to a list using
        #splitlines().

################################################################

activeRSP=activersp()
if activeRSP==None:
        Summary.append('ERROR:\tGetting router information failed, possible reasons:\n\tRouter not started with login page or xr vm')
if activeRSP=='0':
        standbyRSP='1'
else:
        standbyRSP='0'

admin()
wrcom('show platform',1)
out=tn.read_very_eager().decode('utf-8')
print (out)
rsps=[] #Router Processors operational list
lcs=[]  #LCs operational list
out1=out.splitlines()
for i in range(len(out1)):
        match = re.search('([0-9]{1,2})/(RSP*[0-9]{1,2})',out1[i])
        if match:
                match1=re.search('OPERATIONAL   OPERATIONAL',out1[i])
                if match1:
                        if match.group() not in rsps:
                                rsps.append([match.group(),out1[i][9:31].strip(' ')])
        else:
                match = re.search('([0-9]{1,2})/([0-9]{1,2})',out1[i])
                match1=re.search('OPERATIONAL   OPERATIONAL',out1[i])
                if match1:
                        if match:
                                lcs.append([match.group(),out1[i][9:31].strip(' ')])
time.sleep(1)

print(rsps) #optional
print(lcs)  #optional

#mgmt_up(activeRSP)
#gateway_up()

wrcom('show vm location 0/RSP'+activeRSP,3)
out=tn.read_very_eager().decode('utf-8')
out1=out.splitlines()
print(out)
for j in range(len(out1)):
        match1=re.search('default-sdr',out1[j])
        if match1:
                out2=out1[j].split()
                xr_ip=out2[2]
print(xr_ip)

################################################################

        #Case 1:Detect EOBC Link is Up.

################################################################

Summary.append('\nCase 1: Detect EOBC Link is Up.\n')
command2="show controller switch summary location 0/RP"+activeRSP+"/RP-SW"	#ckecking the link state for operational cards from active RSP
tn.write('\n'.encode('utf-8'))
wrcom(command2,3)
out2=tn.read_very_eager().decode('utf-8')
out3=out2.splitlines()
print (out2)
if len(lcs)==0:
        Summary.append('no LC present\n')
for i in range(len(lcs)):
        for j in range(len(out3)):
                match=re.search('LC'+lcs[i][0][2],out3[j])
                if match:
                        if out3[j][6]!='U' :
                                Summary.append("error in LC"+lcs[i][0][2]+'\n')
                                TestCases.append(1)
                        else :
                                Summary.append("no error IN LC"+lcs[i][0][2]+"\n")
if len(rsps)==0:
        Summary.append('both the RPs are not operational\n')
        TestCases.append(1)
elif len(rsps)>1:	#if standby RSP is present then PEER RP link need to be checked
        for i in range(len(out3)):
                match=re.search('PEER RP',out3[i])
                if match:
                        if out3[i][6]!='U' or out3[i+3][6]!='U':
                                Summary.append("error in RSP"+standbyRSP+'\n')
                                TestCases.append(1)
                                break
                        else :
                            Summary.append("no error IN RSPs\n")
                            break
else :
        Summary.append("no error IN RSPs\n")
TestCases=list(set(TestCases))
#if 1 in TestCases :
        #trace('Case1_',xr_ip)

################################################################

		#Case 2:Detecting drops in EOBC

################################################################

Summary.append('\nCase 2: Detecting drops in EOBC\n')

for i in range (len(rsps)):
        command3="show controller switch statistics location 0/RP"+rsps[i][0][5]+"/RP-SW"	#collectiog drops information on various links
        wrcom(command3,3)
        out_stat_loc=tn.read_very_eager().decode('utf-8')
        #print (out_stat_loc)
        out_stat_loc_1=out_stat_loc.splitlines()
        j=0
        for j in range (len(RSPs)):
                if RSPs[j]['board']==rsps[i][1]:
                        break
        if j==len(RSPs)-1:
                Summary.append('Board not present in Dictionary for '+rsps[i][1]+'\n')
        for j in range (len(RSPs)):
                if RSPs[j]['board']==rsps[i][1]:	#collecting information to be parsed for particular board
                        c2_board_parse(RSPs[j]['connection'],out_stat_loc_1)
        for j in range (len(lcs)):	# the information of the present LCs is not present in the created dictionary
                c2_board_parse('LC'+lcs[j][0][2],out_stat_loc_1)
#if 2 in TestCases :
#        trace('Case2_',xr_ip)

################################################################

        #Case 3: Detect VMs livelines

        #Caution: To increase the number of packets while pinging
        #corresponding sleep time must be increased.

################################################################

Summary.append('\nCase 3: Detect VMs liveliness\n')
lcs_ip=[]
rsps_ip=[]
if len(lcs)==0 and len(rsps)==1:
        Summary.append('no ping required\n')
else:
        command_ping_1='show vm'	#collecting the ip address of the different cards (Both Calvados and XR in EXR).
        wrcom(command_ping_1,3)
        out_ping_vm=tn.read_very_eager().decode('utf-8')
        out_ping_vm_1=out_ping_vm.splitlines()
        print (out_ping_vm)
        for i in range (len(lcs)):
                for j in range(len(out_ping_vm_1)):
                        match = re.search(lcs[i][0],out_ping_vm_1[j])
                        if match:
                                for k in range(j,len(out_ping_vm_1)):
                                        match1=re.search('sysadmin',out_ping_vm_1[k])#calvados
                                        if match1:
                                                out_ping_vm_2=out_ping_vm_1[k].split()
                                                lcs_ip.append([lcs[i][0],out_ping_vm_2[2],'Calvados'])
                                        match2=re.search('default-sdr',out_ping_vm_1[k])#XR
                                        if match2:
                                                out_ping_vm_2=out_ping_vm_1[k].split()
                                                lcs_ip.append([lcs[i][0],out_ping_vm_2[2],'XR'])
                                                break
                                break
        for i in range (len(rsps)):
                if rsps[i][0][5]!=activeRSP :
                        for j in range(len(out_ping_vm_1)):
                                match = re.search(rsps[i][0],out_ping_vm_1[j])
                                if match:
                                        for k in range(j,len(out_ping_vm_1)):
                                                match1=re.search('sysadmin',out_ping_vm_1[k])#calvados
                                                if match1:
                                                        out_ping_vm_2=out_ping_vm_1[k].split()
                                                        rsps_ip.append([rsps[i][0],out_ping_vm_2[2],'Calvados'])
                                                match2=re.search('default-sdr',out_ping_vm_1[k])#XR
                                                if match2:
                                                        out_ping_vm_2=out_ping_vm_1[k].split()
                                                        rsps_ip.append([rsps[i][0],out_ping_vm_2[2],'XR'])
                                                        break
                                        break
        wrcom('run',1)
        for i in range(len(lcs_ip)):
                success_lcs=-1
                success_lcs=ping_ip(lcs_ip[i][1],1)
                if success_lcs:
                        Summary.append('ping successful for '+lcs_ip[i][0]+' for '+ lcs_ip[i][2]+'\n')
                else:
                        Summary.append('ping unsuccessful for '+lcs_ip[i][0]+' for '+ lcs_ip[i][2]+'\n')
                        TestCases.append(3)
        for i in range(len(rsps_ip)):
                success_rsps=-1
                success_rsps=ping_ip(rsps_ip[i][1],1)
                if success_rsps:
                        Summary.append('ping successful for '+rsps_ip[i][0]+' for '+ rsps_ip[i][2]+'\n')
                else:
                        Summary.append('ping unsuccessful for '+rsps_ip[i][0]+' for '+ rsps_ip[i][2]+'\n')
                        TestCases.append(3)
        exit()
#if 3 in TestCases :
#        trace('Case3_',xr_ip)

################################################################

        #Case 4:Checking EOBC Traffic Issues from Virtual Functions perspective.

	#To check we get to both the shells by using the run
	#command and then we use the command 'chvrf -0 ifconfig'
	#to get the vf ports information.

################################################################

Summary.append('\nCase 4: Checking EOBC Traffic Issues from Virtual Functions perspective.\n')
wrcom('run',1)
wrcom('chvrf -0 ifconfig eth-vf1.3073',3)
out_vf=tn.read_very_eager().decode('utf-8')
out_vf_1=out_vf.splitlines()
flag_vf=0
for j in range(len(out_vf_1)):	# data parsing
        match=re.search('RX packets',out_vf_1[j])
        if match:
                flag_vf=1 if sear_err('errors','calvados vf',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('dropped','calvados vf',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('overruns','calvados vf',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('frame','calvados vf',out_vf_1[j]) else flag_vf
                break
if flag_vf==0:
        Summary.append('No problems in Calvados VF\n')
exit()
exit()
wrcom('run',1)
wrcom('chvrf -0 ifconfig eth-vf1.3073' ,5)
out_vf=tn.read_very_eager().decode('utf-8')
out_vf_1=out_vf.splitlines()
flag_vf=0
for j in range(len(out_vf_1)):	# data parsing
        match=re.search('RX packets',out_vf_1[j])
        if match:
                flag_vf=1 if sear_err('errors','xr vf(3073)',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('overruns','xr vf(3073)',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('frame','xr vf(3073)',out_vf_1[j]) else flag_vf
                break
wrcom('chvrf -0 ifconfig eth-vf1.3074' ,5)
out_vf=tn.read_very_eager().decode('utf-8')
out_vf_1=out_vf.splitlines()
for j in range(len(out_vf_1)):	# data parsing
        match=re.search('RX packets',out_vf_1[j])
        if match:
                flag_vf=1 if sear_err('errors','xr vf(3074)',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('dropped','xr vf(3074)',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('overruns','xr vf(3074)',out_vf_1[j]) else flag_vf
                flag_vf=1 if sear_err('frame','xr vf(3074)',out_vf_1[j]) else flag_vf
                break
if flag_vf==0:
        Summary.append('No problems in XR VF\n')
exit()  
admin()
#if 4 in TestCases :
#        trace('Case4_',xr_ip)	
    		
################################################################

	#Case 5:Detect VLAN mapping discrepancy.
	#A critical debugging CLI is to find out the current VLAN translations.
	#When RP0 is active, ALL cards must TRANSLATE BLACK VLAN (0xC00 base) to BLUE VLAN (0x800 base) and vice-versa at the CPU port.
	#When RP0 is active, ALL cards must DROP RED VLAN (0x400 base) packets at the CPU port.
	#When RP1 is active, ALL cards must TRANSLATE BLACK VLAN (0xC00 base) to RED VLAN (0x400 base) and vice-versa at the CPU port.
	#When RP1 is active, ALL cards must DROP BLUE VLAN (0x800 base) packets at the CPU port


################################################################
Summary.append('\nCase 5: Detect VLAN mapping discrepancy.\n')
rsps_port=[]
lcs_port=[]
blue_ports=['2049','2050']	#blue VLAN ports
red_ports=['1025','1026']	#red VLAN ports

for i in range (len(rsps)):
        command_summ='show controller switch summary location 0/RP'+rsps[i][0][5]+'/RP-SW'	#getting EOBC port numbers for each RSP
        wrcom(command_summ,3)
        out_summ=tn.read_very_eager().decode('utf-8')
        out_summ_1=out_summ.splitlines()
        for j in range (len(out_summ_1)):
                match = re.search('EOBC',out_summ_1[j])
                if match:
                        rsps_port.append([rsps[i][0],out_summ_1[j][0:2]])
for i in range (len(lcs)):
        command_summ='show controller switch summary location 0/LC'+lcs[i][0][2]+'/LC-SW'	#getting CPU N1 port numbers for each LC
        wrcom(command_summ,3)
        out_summ=tn.read_very_eager().decode('utf-8')
        out_summ_1=out_summ.splitlines()
        for j in range (len(out_summ_1)):
                match = re.search('CPU N1',out_summ_1[j])
                if match:
                        lcs_port.append([lcs[i][0],out_summ_1[j][0:2]])
#print(rsps_port)
#print(lcs_port)
flag_vlan_rsps=0

for i in range (len(rsps_port)):
        command_vlan='show controller switch vlan rules location 0/RP'+rsps[i][0][5]+'/RP-SW '+rsps_port[i][1]	#vlan rules output to parse for RSPs
        out_vlan_1=parse(command_vlan,5)
        for k in range (len(out_vlan_1)):
                flag_vlan_rsps=1 if sear_ptype('red',red_ports,'RSP'+rsps_port[i][0][5],out_vlan_1[k])!=None else flag_vlan_rsps
                flag_vlan_rsps=1 if sear_ptype('blue',blue_ports,'RSP'+rsps_port[i][0][5],out_vlan_1[k])!=None else flag_vlan_rsps

if flag_vlan_rsps==0:
        Summary.append('No error in RSPs ports\n')
flag_vlan_lcs=0
	
for i in range (len(lcs_port)):
        command_vlan='show controller switch vlan rules location 0/LC'+lcs[i][0][2]+'/LC-SW '+lcs_port[i][1]	#vlan rules output to parse for LCs
        out_vlan_1=parse(command_vlan,5)
        for k in range (len(out_vlan_1)):
                flag_vlan_lcs=1 if sear_ptype('red',red_ports,'LC'+lcs_port[i][0][2],out_vlan_1[k])!=None else flag_vlan_lcs
                flag_vlan_lcs=1 if sear_ptype('blue',blue_ports,'LC'+lcs_port[i][0][2],out_vlan_1[k])!=None else flag_vlan_lcs
	
if flag_vlan_lcs==0 :
        Summary.append('No error in LCs ports\n')
#if 5 in TestCases :
 #       trace('Case5_',xr_ip)


################################################################

	#Case 6:Detect Stuck VQIs on LCs


################################################################

Summary.append('\nCase 6: Detect Stuck VQIs on LCs\n')
exit()
dest=[]
for i in range (len(lcs)):
        command_qdep='show controllers fabric fia q-depth location 0/'+lcs[i][0][2]+'/CPU0'	#checking for VOQ errors
        wrcom(command_qdep,3)
        out_qdep=tn.read_very_eager().decode('utf-8')
        out_qdep_1=out_qdep.splitlines()
        out_qdep_1.pop()
        #print(out_qdep)
        for j in range (len(out_qdep_1)):
                match = re.search('Voq',out_qdep_1[j])
                if match:
                        for k in range (j+1,len(out_qdep_1)):
                                if len(out_qdep_1[k])>1:
                                        match1 = re.search('FIA',out_qdep_1[k])
                                        if match1 :
                                                break
                                        else :
                                                TestCases.append(6)
                                                out_qdep_2=out_qdep_1[k].split()
                                                dest_lc=out_qdep_2[-1][2]	#getting the LC with stuck VQIs
                                                if dest_lc not in dest:
                                                        Summary.append('Voq errors for LC'+dest_lc+'\n')
                                                        cmd_arb='show controllers fabric arbiter link-status location 0/RSP'+activeRSP+'/CPU0'	#finding port associated with LC on CARB
                                                        wrcom(cmd_arb,2)
                                                        out_carb=tn.read_very_eager().decode('utf-8')
                                                        out_carb_1=out_carb.splitlines()
                                                        dest.append(dest_lc)
                                                        for l in range (len(out_carb_1)):
                                                                match2 = re.search('0/'+dest_lc+'/CPU0',out_carb_1[l])
                                                                if match2:
                                                                        dest_port_1=out_carb_1[l].split()
                                                                        dest_port=dest_port_1[0]
                                                                        wrcom('run',2)
                                                                        cmd_fab='fabarb_client_test'	#running client test and getting stats for the port
                                                                        wrcom(cmd_fab,3)
                                                                        tn.write(('\n').encode('utf-8'))
                                                                        time.sleep(1)
                                                                        cmd_stats='stats '+dest_port
                                                                        wrcom(cmd_stats,10)
                                                                        out_stats_port=tn.read_very_eager().decode('utf-8')
                                                                        out_stats_port_1=out_stats_port.splitlines()
                                                                        #print(out_stats_port_1)
                                                                        for m in range(len(out_stats_port_1)):
                                                                                match3 = re.search('Stuck VQIs on XIF : ',out_stats_port_1[m]) #parsing for stuck VQIs
                                                                                if match3:
                                                                                        for n in range(m+1,len(out_stats_port_1)):
                                                                                                if len(out_stats_port_1[n])>1 :
                                                                                                        if out_stats_port_1[n][0]!='=':
                                                                                                                match4=re.search('Credits Available',out_stats_port_1[n])
                                                                                                                if match4:
                                                                                                                        break
                                                                                                                else :
                                                                                                                        Summary.append('\t'+out_stats_port_1[n]+'\n')
                                                                        wrcom('quit',1)
                                                                        exit()
                                                                        break
if len(dest)==0:
        Summary.append('No Voq errors\n')
admin()

################################################################

	#Case 7:Triaging l2fib_mgr crash


################################################################								


Summary.append('\nCase 7: Triaging l2fib_mgr crash\n')
exit()
cmd_fablib='show  processes l2fib_mgr'
wrcom(cmd_fablib,3)
out_fablib=tn.read_very_eager().decode('utf-8')
out_fablib_1=out_fablib.splitlines()
#print(out_fablib)
for i in range (len(out_fablib_1)):
        match = re.search('Respawn count',out_fablib_1[i])
        if match:
                out_fablib_2=out_fablib_1[i].split()
                count=out_fablib_2[-1]
                time.sleep(10)
                wrcom(cmd_fablib,3)
                out_fablib_3=tn.read_very_eager().decode('utf-8')
                out_fablib_4=out_fablib_3.splitlines()
                #print(out_fablib_3)
                for j in range (len(out_fablib_4)):
                        match1 = re.search('Respawn count',out_fablib_4[j])
                        if match1:
                                out_fablib_5=out_fablib_4[j].split()
                                count1=out_fablib_5[-1]
                                #print(count,count1)	
                                if count1!=count:	#comparing respawn count at two instances differing 10s
                                        TestCases.append(7)
                                        cmd_logs='show logging | i abnormally terminated, restart scheduled'	#checking logs for abnormality in termination of process
                                        wrcom(cmd_logs,5)
                                        out_logs=tn.read_very_eager().decode('utf-8')
                                        out_logs_1=out_logs.splitlines()
                                        out_logs_1=out_logs_1[1:len(out_logs_1)]
                                        first_resp='0'
                                        for k in range (len(out_logs_1)):
                                                match2 = re.search('abnormally terminated, restart scheduled',out_logs_1[k])
                                                if match2:
                                                        first_resp=out_logs_1[k].split()[2]
                                                        break
                                        if first_resp=='0':
                                                Summary.append('unknown reason may be manual\n')
                                        else :
                                                cmd_logs_1='show logging | i l2fib | i Failed to register with multicast fabric'	#if teminated abnormally, checking the reason
                                                wrcom(cmd_logs_1,2)
                                                out_logs_2=tn.read_very_eager().decode('utf-8')
                                                out_logs_3=out_logs_2.splitlines()
                                                out_logs_3=out_logs_3[1:len(out_logs_1)]
                                                first_fib='0'
                                                for k in range (len(out_logs_3)):
                                                        match2 = re.search('Failed to register with multicast fabric',out_logs_3[k])
                                                        if match2:
                                                                first_fib=out_logs_3[k].split()[2]
                                                                err_lc=out_logs_3[k].split()[0][5]
                                                                Summary.append('l2fib failed to register with multicast fabric\n')
                                                                break
                                                if first_fib!='0' :
                                                        FMT = '%H:%M:%S.%f'
                                                        diff=datetime.strptime(first_resp, FMT) - datetime.strptime(first_fib, FMT)
                                                        #print(first_fib,first_resp,diff)
                                                        if diff.microseconds>0 and diff.microseconds<50000 :	#the above two ckecks must differ by small amount of time
                                                                cmd_trace='show controllers fabric fia trace location 0/'+err_lc+'/CPU0 | i failed to do serdes and ddr download'
                                                                wrcom(cmd_trace,2)
                                                                out_trace=tn.read_very_eager().decode('utf-8')
                                                                out_trace_1=out_trace.splitlines()
                                                                out_trace_1=out_trace_1[1:len(out_logs_1)]
                                                                for k in range (len(out_trace_1)):
                                                                        match2=re.search('failed to do serdes and ddr download',out_trace_1[k]) #finding the reason
                                                                        if match2 :
                                                                                out_trace_2=out_trace_1[k].split()[8]
                                                                                Summary.append('FIA ASIC-'+out_trace_2[-1]+' failed to complete initialization due to serdes and ddr download failure.\n')
                                                                                break
                                                                        if k==len(out_trace_1)-1:
                                                                                Summary.append('unknown reason\n')	#other non included reasons for crash
                                                        else:
                                                                Summary.append('unknown reason\n')	#other non included reasons for crash
                                                else :
                                                        Summary.append('unknown reason might be due to other process than l2fib_mgr\n')	#restart abnormality due to some other process
                                else:
                                        Summary.append('No problems in process l2fib_mgr\n')	#respawn count not changing
                                break
                break

admin()	

print(TestCases)
TestCases=list(set(TestCases))
Summary=''.join(Summary)
f=open('results.txt','w')
if len(TestCases)>0:
        f.write('No. of Test Cases Passed = '+str(7-len(TestCases))+'\nNo. of Test Cases Failed = '+str(len(TestCases))+'\nFailed Test Cases:\n')
        for i in range (7):
                if i+1 in TestCases :
                        f.write('Test Case '+str(i+1)+'\n')
else :
        f.write('All Test Cases Passed\n\n')
f.close()
fs=open('summary.txt','w')
fs.write(Summary.strip())
fs.close()
Summary=''.join(Summary)
print(Summary)
exit()
exit()
tn.close()
