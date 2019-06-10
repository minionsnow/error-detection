#import paramiko
import telnetlib
import time
import re
import sys
#import warnings
#from . import data_file
from data_file import RSPs
from datetime import datetime
#RSPs=data_file.RSPs
#warnings.filterwarnings("ignore")

#LCs={1:{'board':'A9K-16X100GE-TR','2':'','lc':'0','port':'48'},
#     2:{'board':'','2':'','lc':'','port':''}}

#ssh1=paramiko.SSHClient()
#ssh2=paramiko.SSHClient()
#ssh1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#ssh1.connect('bgl-ads-1534',username='ypandit',password='Yhre321#78')
#time.sleep(1)
#ssh2.connect('10.105.226.158',username='root',password='Ci$c0@321')
#time.sleep(1)
#ssh2.exec_command('cd /nobackup/ypandit/')

################################################################

        #Initilization of the initial parameters like the
        #hostname,console,username,password.

################################################################

host=sys.argv[1]
#host='10.105.226.89'
#host='10.105.226.158'
#host='10.105.226.249'
#host='10.105.226.74'
#host='10.105.226.68'
#host='10.105.226.207'
console=sys.argv[2]
#console=2058
#console = 27752
#console=2031
#console=2021
#console=2034
timeout=3
username=sys.argv[3]
#username='root'
password=sys.argv[4]
#password='lab123'
print(console,host,username,password)
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
Summary.append('\n\nSummary:\n\n')
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

command1="show platform"
#filename='maping.txt'
tn.write((command1 + '\n').encode('utf-8'))
time.sleep(2)
out=tn.read_very_eager().decode('utf-8')
out1=out.splitlines()
for i in range (len(out1)):
    match=re.search('Active',out1[i])
    if match:
        activeRSP=out1[i][5]
print(out)
if activeRSP=='0':
	n_activeRSP='1'
else:
	n_activeRSP='0'
tn.write(('admin'+'\n').encode('utf-8'))
time.sleep(2)
tn.write((command1 + '\n').encode('utf-8'))
time.sleep(1)
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
################################################################

        #Case 1:
        #To check the error present in the physical state of the
        #the cards like LCs and RSPs in the switches by
        #crosschecking the output of command2 below for the
        #Operational cards we got above.

################################################################

Summary.append('\nCase 1: Checking physical state of cards\n')
command2="show controller switch summary location 0/RP"+activeRSP+"/RP-SW"
tn.write('\n'.encode('utf-8'))
tn.write((command2 + '\n').encode('utf-8'))
time.sleep(3)
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
            else :
                Summary.append("no error IN LCs\n")
if len(rsps)==0:
    Summary.append('both the RPs are not operational\n')
elif len(rsps)>1:
    for i in range(len(out3)):
        match=re.search('PEER RP',out3[i])
        if match:
            if out3[i][6]!='U' or out3[i+3][6]!='U':
                Summary.append("error in RSP"+n_activeRSP+'\n')
                break
            else :
                Summary.append("no error IN RSPs\n")
                break
else :
    Summary.append("no error IN RSPs\n")

################################################################

		#Case 2:

################################################################

'''with open('stat.txt') as f:
    out_stat_loc_1= f.read().splitlines()
with open('stat_det.txt') as fs:
    out_stat_det_1= fs.read().splitlines()'''

Summary.append('\nCase 2: Checking connections of RSPs\n')
for i in range (len(rsps)):
    command3="show controller switch statistics location 0/RP"+rsps[i][0][5]+"/RP-SW"
    tn.write((command3 + '\n').encode('utf-8'))
    time.sleep(3)
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
        if RSPs[j]['board']==rsps[i][1]:
            for k in range (len(out_stat_loc_1)):
                match=re.search(RSPs[j]['connection'],out_stat_loc_1[k])
                if match:
                    out_stat_loc_2=out_stat_loc_1[k].split()
                    port=out_stat_loc_2[0]
                    flag_tx=0
                    flag_rx=0
                    if out_stat_loc_2[1]!='Up':
                        Summary.append(RSPs[j]['connection']+'is not Up')
                    else:
                        if out_stat_loc_2[5]!='0':
                            Summary.append('Tx drop in '+RSPs[j]['connection']+' : Reason : \n')
                            flag_tx=1
                        if out_stat_loc_2[6]!='0':
                            Summary.append('Rx drop in '+RSPs[j]['connection']+' : Reason : \n')
                            flag_rx=1
                        if flag_tx!=0 or flag_rx!=0:
                            command4="show controller switch statistics detail location 0/RP"+rsps[i][0][5]+"/RP-SW "+port
                            tn.write((command4 + '\n').encode('utf-8'))
                            time.sleep(3)
                            out_stat_det=tn.read_very_eager().decode('utf-8')
                            out_stat_det_1=out_stat_det.splitlines()
                            for l in range (len(out_stat_det_1)):
                                match1=re.search('Rx Errors',out_stat_det_1[l])
                                if match1:
                                    out_stat_det_2=out_stat_det_1[l].split()
                                    if out_stat_det_2[-1]!='0':
                                        Summary.append('\tRx Errors\n')
                                match2=re.search('Rx Bad CRC',out_stat_det_1[l])
                                if match2:
                                    out_stat_det_2=out_stat_det_1[l].split()
                                    if out_stat_det_2[-1]!='0':
                                        Summary.append('\tRx Bad CRC\n')
                                match3=re.search('Rx Policing Drops',out_stat_det_1[l])
                                if match3:
                                    out_stat_det_2=out_stat_det_1[l].split()
                                    if out_stat_det_2[-1]!='0':
                                        Summary.append('\tRx Policing Drops\n')
                                    if flag_tx==0 and flag_rx==0:
                                        Summary.append('no drop in '+RSPs[j]['connection']+' For '+rsps[i][0]+'\n')
    for j in range (len(lcs)):
        for k in range (len(out_stat_loc_1)):
            match=re.search('LC'+lcs[j][0][2],out_stat_loc_1[k])
            if match:
                out_stat_loc_2=out_stat_loc_1[k].split()
                port=out_stat_loc_2[0]
                flag_tx=0
                flag_rx=0
                if out_stat_loc_2[1]!='Up':
                    Summary.append(RSPs[j]['connection']+'is not Up\n')
                else:
                    if out_stat_loc_2[5]!='0':
                        Summary.append('Tx drop in '+'LC'+lcs[j][0][2]+' : Reason : \n')
                        flag_tx=1
                    if out_stat_loc_2[6]!='0':
                        Summary.append('Rx drop in '+'LC'+lcs[j][0][2]+' : Reason : \n')
                        flag_rx=1
                    if flag_tx!=0 or flag_rx!=0:
                        command4="show controller switch statistics detail location 0/RP"+rsps[i][0][5]+"/RP-SW "+port
                        tn.write((command4 + '\n').encode('utf-8'))
                        time.sleep(3)
                        out_stat_det=tn.read_very_eager().decode('utf-8')
                        out_stat_det_1=out_stat_det.splitlines()
                        for l in range (len(out_stat_det_1)):
                            match1=re.search('Rx Errors',out_stat_det_1[l])
                            if match1:
                                out_stat_det_2=out_stat_det_1[l].split()
                                if out_stat_det_2[-1]!='0':
                                    Summary.append('\tReason: Rx Errors\n')
                            match2=re.search('Rx Bad CRC',out_stat_det_1[l])
                            if match2:
                                out_stat_det_2=out_stat_det_1[l].split()
                                if out_stat_det_2[-1]!='0':
                                    Summary.append('\tReason: Rx Bad CRC\n')
                            match3=re.search('Rx Policing Drops',out_stat_det_1[l])
                            if match3:
                                out_stat_det_2=out_stat_det_1[l].split()
                                if out_stat_det_2[-1]!='0':
                                    Summary.append('\tReason: Rx Policing Drops\n')
                if flag_tx==0 and flag_rx==0:
                    Summary.append('no drop in '+'LC'+lcs[j][0][2]+' For '+rsps[i][0]+'\n')

################################################################

        #Case 3: We try to ping different cards present from
        #the calvados shell to check their health.

        #Command 'show vm' is to collect the ip address of the
        #different cards (Both Calvados and XR in EXR).

        #To get into the calvados shell we used command 'run'
        #in admin.

        #To ping we used command "chvrf 0 ping '+lcs_ip[i][1]+'
        #-c 2' + '\n'"(example for lcs),chvrf due to extra
        #security and 2 at the end for number of packets sent.

        #Caution: To increase the number of packets
        #corresponding sleep time must be increased.

################################################################

Summary.append('\nCase 3: Checking health of Cards by pinging them\n')
lcs_ip=[]
rsps_ip=[]
if len(lcs)==0 and len(rsps)==1:
    Summary.append('no ping required\n')
else:
    command_ping_1='show vm'
    tn.write((command_ping_1 + '\n').encode('utf-8'))
    time.sleep(3)
    out_ping_vm=tn.read_very_eager().decode('utf-8')
    out_ping_vm_1=out_ping_vm.splitlines()
    #print (out_ping_vm)
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
    tn.write(('run' + '\n').encode('utf-8'))# to get into shell calvados
    time.sleep(1)
    #lcs_ip[0][1]='192.16.16.2'
    for i in range(len(lcs_ip)):
        tn.write(('chvrf 0 ping '+lcs_ip[i][1]+' -c 2' + '\n').encode('utf-8'))
        time.sleep(3)
        out_ping_shell=tn.read_very_eager().decode('utf-8')
        match=re.search(', 0% packet loss',out_ping_shell)
        if match:
            Summary.append('ping successful for '+lcs_ip[i][0]+' for '+ lcs_ip[i][2]+'\n')
        else:
            Summary.append('ping unsuccessful for '+lcs_ip[i][0]+' for '+ lcs_ip[i][2]+'\n')
    for i in range(len(rsps_ip)):
        tn.write(('chvrf 0 ping '+rsps_ip[i][1]+' -c 2' + '\n').encode('utf-8'))
        time.sleep(3)
        out_ping_shell=tn.read_very_eager().decode('utf-8')
        match=re.search(', 0% packet loss',out_ping_shell)
        if match:
            Summary.append('ping successful for '+rsps_ip[i][0]+' for '+ rsps_ip[i][2]+'\n')
        else:
            Summary.append('ping unsuccessful for '+rsps_ip[i][0]+' for '+ rsps_ip[i][2]+'\n')
    tn.write(('exit'+'\n').encode('utf-8'))
    time.sleep(2)

################################################################

        #Case 4:To check the errors,drops,overruns & frames in 
	#the vf (both the calvados and xr).

	#To check we get to both the shells by using the run
	#command and then we use the command 'chvrf -0 ifconfig'
	#to get the vf ports information (to be parsed for the
	#errors)

	#we started with the fact that we are already in the 
	#admin.

################################################################

Summary.append('\nCase 4: Checking errors in VFs\n')
tn.write(('run' + '\n').encode('utf-8'))	# to get into calvados shell
time.sleep(1)
tn.write(('chvrf -0 ifconfig' + '\n').encode('utf-8'))	# ports information
time.sleep(3)	#depends on the information taken
out_vf_cal=tn.read_very_eager().decode('utf-8')
out_vf_cal_1=out_vf_cal.splitlines()
flag_vf_cal=0

for i in range(len(out_vf_cal_1)):
    match=re.search('eth-vf1.3073',out_vf_cal_1[i]) 	# virtual port to connect with calvados
    if match:
        for j in range(i,len(out_vf_cal_1)):	# data parsing
                match1=re.search('errors',out_vf_cal_1[j])
                if match1:
                    match2=re.search('errors:0',out_vf_cal_1[j])
                    if match2==None:
                        flag_vf_cal=1
                        Summary.append('\terror in calvados vf\n')
                match1=re.search('dropped',out_vf_cal_1[j])
                if match1:
                    match2=re.search('dropped:0',out_vf_cal_1[j])
                    if match2==None:
                        flag_vf_cal=1
                        Summary.append('\tdrops in calvados vf\n')
                match1=re.search('overruns',out_vf_cal_1[j])
                if match1:
                    match2=re.search('overruns:0',out_vf_cal_1[j])
                    if match2==None:
                        flag_vf_cal=1
                        Summary.append('\toverruns in calvados vf\n')
                match1=re.search('frame',out_vf_cal_1[j])
                if match1:
                    match2=re.search('frame:0',out_vf_cal_1[j])
                    if match2==None:
                        flag_vf_cal=1
                        Summary.append('\tframesin calvados vf\n')
                    break
        break
if flag_vf_cal==0:
    Summary.append('No problems in Calvados VF\n')
tn.write(('exit'+'\n').encode('utf-8'))	# exiting calvados shell
time.sleep(1)
tn.write(('exit'+'\n').encode('utf-8'))	# exiting calvados
time.sleep(1)
tn.write(('run' + '\n').encode('utf-8'))# to get into xr shell
time.sleep(1)
tn.write(('chvrf -0 ifconfig' + '\n').encode('utf-8'))
time.sleep(5)
out_vf_xr=tn.read_very_eager().decode('utf-8')
out_vf_xr_1=out_vf_xr.splitlines()
flag_vf_xr=0

for i in range(len(out_vf_xr_1)):
    match=re.search('eth-vf1.3073',out_vf_xr_1[i])	#virtual port for xr to calvados connection
    if match:
        for j in range(i,len(out_vf_xr_1)):	# data parsing
            match1=re.search('errors',out_vf_xr_1[j])
            if match1:
                match2=re.search('errors:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\terror in xr vf(3073)\n')
            match1=re.search('overruns',out_vf_xr_1[j])
            if match1:
                match2=re.search('overruns:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\toverruns in xr vf(3073)\n')
            match1=re.search('frame',out_vf_xr_1[j])
            if match1:
                match2=re.search('frame:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\tframes in xr vf(3073)\n')
                break
    match=re.search('eth-vf1.3074',out_vf_xr_1[i])	# virtual port to connect to xr
    if match:
        for j in range(i,len(out_vf_xr_1)):	# data parsing
            match1=re.search('errors',out_vf_xr_1[j])
            if match1:
                match2=re.search('errors:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\terror in xr vf(3074)\n')
            match1=re.search('dropped',out_vf_xr_1[j])
            if match1:
                match2=re.search('dropped:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\tdrops in xr vf(3074)\n')
            match1=re.search('overruns',out_vf_xr_1[j])
            if match1:
                match2=re.search('overruns:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\toverruns in xr vf(3074)\n')
            match1=re.search('frame:0',out_vf_xr_1[j])
            if match1:
                match2=re.search('frame:0',out_vf_xr_1[j])
                if match2==None:
                    flag_vf_xr=1
                    Summary.append('\tframesin xr vf(3074)\n')
                break
        break
if flag_vf_xr==0:
    Summary.append('No problems in XR VF\n')
tn.write(('exit'+'\n').encode('utf-8'))	# exiting calvados shell
time.sleep(1)
tn.write(('admin'+'\n').encode('utf-8'))	# getting back to admin
time.sleep(2)   
	    		
################################################################

	#Case 5:

################################################################
Summary.append('\nCase 5: Chcking errors in VLANs\n')
rsps_port=[]
lcs_port=[]
blue_ports=['2049','2050']
red_ports=['1025','1026']

if activeRSP=='0' :
    flag_ports=0
else :
    flag_ports=1
for i in range (len(rsps)):
    command_summ='show controller switch summary location 0/RP'+rsps[i][0][5]+'/RP-SW'
    tn.write((command_summ+'\n').encode('utf-8'))	
    time.sleep(3)
    out_summ=tn.read_very_eager().decode('utf-8')
    out_summ_1=out_summ.splitlines()
    for j in range (len(out_summ_1)):
        match = re.search('EOBC',out_summ_1[j])
        if match:
            rsps_port.append([rsps[i][0],out_summ_1[j][0:2]])
for i in range (len(lcs)):
    command_summ='show controller switch summary location 0/LC'+lcs[i][0][2]+'/LC-SW'
    tn.write((command_summ+'\n').encode('utf-8'))	
    time.sleep(3)
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
    command_vlan='show controller switch vlan rules location 0/RP'+rsps[i][0][5]+'/RP-SW'
    tn.write((command_vlan+'\n').encode('utf-8'))	
    time.sleep(5)
    out_vlan=tn.read_very_eager().decode('utf-8')
    out_vlan_1=out_vlan.splitlines()
    #print(out_vlan)
    for j in range (len(out_vlan_1)):
        if out_vlan_1[j][0:2]==rsps_port[i][1]:
            for k in range (j+1,len(out_vlan_1)):
                if len(out_vlan_1[k])>1:
                    if out_vlan_1[k][0].isnumeric():
                        break
                for l in range (len(red_ports)):
                    match1=re.search(red_ports[l],out_vlan_1[k])
                    if match1 and out_vlan_1[k][0]==' ' :
                        if flag_ports==0:
                            match2=re.search('Drop',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_rsps=1
                                Summary.append('error in red_port '+red_ports[l]+' in RSP'+rsps_port[i][0][5]+'\n')
                        else :
                            match2=re.search('Translate',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_rsps=1
                                Summary.append('error in red_port '+red_ports[l]+' in RSP'+rsps_port[i][0][5]+'\n')
                for l in range (len(blue_ports)):
                    match1=re.search(blue_ports[l],out_vlan_1[k])
                    if match1 and out_vlan_1[k][0]==' ':
                        if flag_ports==1:
                            match2=re.search('Drop',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_rsps=1
                                Summary.append('error in blue_port '+blue_ports[l]+' in RSP'+rsps_port[i][0][5]+'\n')
                        else :
                            match2=re.search('Translate',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_rsps=1
                                Summary.append('error in blue_port '+blue_ports[l]+' in RSP'+rsps_port[i][0][5]+'\n')
            break

if flag_vlan_rsps==0:
    Summary.append('No error in RSPs ports\n')
flag_vlan_lcs=0
	
for i in range (len(lcs_port)):
    command_vlan='show controller switch vlan rules location 0/LC'+lcs[i][0][2]+'/LC-SW'
    tn.write((command_vlan+'\n').encode('utf-8'))	
    time.sleep(5)
    out_vlan=tn.read_very_eager().decode('utf-8')
    out_vlan_1=out_vlan.splitlines()
    #print(out_vlan)
    for j in range (len(out_vlan_1)):
        if out_vlan_1[j][0:2]==lcs_port[i][1]:
            for k in range (j+1,len(out_vlan_1)):
                if len(out_vlan_1[k])>1:
                    if out_vlan_1[k][0].isnumeric():
                        break
                for l in range (len(red_ports)):
                    match1=re.search(red_ports[l],out_vlan_1[k])
                    if match1 and out_vlan_1[k][0]==' ' :
                        if flag_ports==0:
                            match2=re.search('Drop',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_lcs=1
                                Summary.append('error in red_port '+red_ports[l]+' in LC'+lcs_port[i][0][2]+'\n')
                        else :
                            match2=re.search('Translate',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_lcs=1
                                Summary.append('error in red_port '+red_ports[l]+' in LC'+lcs_port[i][0][2]+'\n')
                for l in range (len(blue_ports)):
                    match1=re.search(blue_ports[l],out_vlan_1[k])
                    if match1 and out_vlan_1[k][0]==' ':
                        if flag_ports==1:
                            match2=re.search('Drop',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_lcs=1
                                Summary.append('error in blue_port '+blue_ports[l]+' in LC'+lcs_port[i][0][2]+'\n')
                        else :
                            match2=re.search('Translate',out_vlan_1[k])
                            if match2==None:
                                flag_vlan_lcs=1
                                Summary.append('error in blue_port '+blue_ports[l]+' in LC'+lcs_port[i][0][2]+'\n')
            break
if flag_vlan_lcs==0 :
    Summary.append('No error in LCs ports\n')
################################################################

	#Case 6:PCI

################################################################
'''
tn.write(('run'+'\n').encode('utf-8'))
time.sleep(1)
command_host='chvrf 0 ssh my_host'
tn.write((command_host+'\n').encode('utf-8'))	
time.sleep(1)
command_pci='lspci -nn | grep Cisco'
tn.write((command_pci+'\n').encode('utf-8'))	
time.sleep(2)			
out_pci=tn.read_very_eager().decode('utf-8')
out_pci_1=out_pci.splitlines()
print(out_pci)
tn.write(('exit'+'\n').encode('utf-8'))
time.sleep(1)
tn.write(('exit'+'\n').encode('utf-8'))
time.sleep(1)'''

################################################################

	#Case 7:Fabric

################################################################
'''with open('new_stats.txt') as f:
    out_stats_port_1= f.read().splitlines()
with open('new_stats_1.txt') as fs:
    out_qdep_1= fs.read().splitlines()'''

Summary.append('\nCase 7: Fabric\n')
tn.write(('exit'+'\n').encode('utf-8'))
time.sleep(1)
dest=[]
for i in range (len(lcs)):
    command_qdep='show controllers fabric fia q-depth location 0/'+lcs[i][0][2]+'/CPU0'
    tn.write((command_qdep+'\n').encode('utf-8'))	
    time.sleep(3)
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
                        out_qdep_2=out_qdep_1[k].split()
                        dest_lc=out_qdep_2[-1][2]
                        if dest_lc not in dest:
                            Summary.append('Voq errors for LC'+dest_lc+'\n')
                            cmd_arb='show controllers fabric arbiter link-status location 0/RSP'+activeRSP+'/CPU0'
                            tn.write((cmd_arb+'\n').encode('utf-8'))	
                            time.sleep(2)
                            out_carb=tn.read_very_eager().decode('utf-8')
                            out_carb_1=out_carb.splitlines()
                            dest.append(dest_lc)
                            for l in range (len(out_carb_1)):
                                match2 = re.search('0/'+dest_lc+'/CPU0',out_carb_1[l])
                                if match2:
                                    dest_port_1=out_carb_1[l].split()
                                    dest_port=dest_port_1[0]
                                    tn.write(('run'+'\n').encode('utf-8'))	
                                    time.sleep(2)
                                    cmd_fab='fabarb_client_test'
                                    tn.write((cmd_fab+'\n').encode('utf-8'))
                                    time.sleep(3)
                                    tn.write(('\n').encode('utf-8'))
                                    time.sleep(1)
                                    cmd_stats='stats '+dest_port
                                    tn.write((cmd_stats+'\n').encode('utf-8'))
                                    time.sleep(10)
                                    out_stats_port=tn.read_very_eager().decode('utf-8')
                                    out_stats_port_1=out_stats_port.splitlines()
                                    #print(out_stats_port_1)
                                    for m in range(len(out_stats_port_1)):
                                        match3 = re.search('Stuck VQIs on XIF : ',out_stats_port_1[m])
                                        if match3:
                                            for n in range(m+1,len(out_stats_port_1)):
                                                if len(out_stats_port_1[n])>1 :
                                                    if out_stats_port_1[n][0]!='=':
                                                        match4=re.search('Credits Available',out_stats_port_1[n])
                                                        if match4:
                                                            break
                                                        else :
                                                            Summary.append('\t'+out_stats_port_1[n]+'\n')
                                    tn.write(('quit'+'\n').encode('utf-8'))
                                    time.sleep(1)
                                    tn.write(('exit'+'\n').encode('utf-8'))
                                    time.sleep(1)
                                    break
if len(dest)==0:
    Summary.append('No Voq errors\n')
tn.write(('admin'+'\n').encode('utf-8'))
time.sleep(2)
################################################################

	#Case 8:Fabric_2

################################################################								
'''with open('logs.txt') as f:
    out_logs_1= f.read().splitlines()
with open('logs_1.txt') as fs:
    out_fablib_4= fs.read().splitlines()
with open('logs_2.txt') as fa:
    out_logs_3= fa.read().splitlines()
with open('trace.txt') as fb:
    out_trace_1= fb.read().splitlines()'''

Summary.append('\nCase 8: Fabric_2\n')
tn.write(('exit'+'\n').encode('utf-8'))
time.sleep(1)
cmd_fablib='show  processes l2fib_mgr'
tn.write((cmd_fablib+'\n').encode('utf-8'))	
time.sleep(3)
out_fablib=tn.read_very_eager().decode('utf-8')
out_fablib_1=out_fablib.splitlines()
#print(out_fablib)
for i in range (len(out_fablib_1)):
    match = re.search('Respawn count',out_fablib_1[i])
    if match:
        out_fablib_2=out_fablib_1[i].split()
        count=out_fablib_2[-1]
        time.sleep(10)
        tn.write((cmd_fablib+'\n').encode('utf-8'))	
        time.sleep(3)
        out_fablib_3=tn.read_very_eager().decode('utf-8')
        out_fablib_4=out_fablib_3.splitlines()
        #print(out_fablib_3)
        for j in range (len(out_fablib_4)):
            match1 = re.search('Respawn count',out_fablib_4[j])
            if match1:
                out_fablib_5=out_fablib_4[j].split()
                count1=out_fablib_5[-1]
                #print(count,count1)	
                if count1!=count:
                    cmd_logs='show logging | i abnormally terminated, restart scheduled'
                    tn.write((cmd_logs+'\n').encode('utf-8'))	
                    time.sleep(5)
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
                        cmd_logs_1='show logging | i l2fib | i Failed to register with multicast fabric'
                        tn.write((cmd_logs_1+'\n').encode('utf-8'))	
                        time.sleep(2)
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
                            if diff.microseconds>0 and diff.microseconds<50000 :
                                cmd_trace='show controllers fabric fia trace location 0/'+err_lc+'/CPU0 | i failed to do serdes and ddr download'
                                tn.write((cmd_trace+'\n').encode('utf-8'))	
                                time.sleep(2)
                                out_trace=tn.read_very_eager().decode('utf-8')
                                out_trace_1=out_trace.splitlines()
                                out_trace_1=out_trace_1[1:len(out_logs_1)]
                                for k in range (len(out_trace_1)):
                                    match2=re.search('failed to do serdes and ddr download',out_trace_1[k])
                                    if match2 :
                                        out_trace_2=out_trace_1[k].split()[8]
                                        Summary.append('FIA ASIC-'+out_trace_2[-1]+' failed to complete initialization due to serdes and ddr download failure.\n')
                                        break
                                    if k==len(out_trace_1)-1:
                                        Summary.append('unknown reason\n')
                            else:
                                Summary.append('unknown reason\n')
                        else :
                            Summary.append('unknown reason might be due to other process than l2fib_mgr\n')
                else:
                    Summary.append('No problems in process l2fib_mgr\n')
                break
        break

tn.write(('admin'+'\n').encode('utf-8'))
time.sleep(2)

Summary=''.join(Summary)
fs=open('summary.txt','w')
fs.write(Summary)
fs.close()
print(Summary)
tn.write(('exit'+'\n').encode('utf-8'))
time.sleep(1)
tn.write(('exit'+'\n').encode('utf-8'))
time.sleep(1)
tn.close()

