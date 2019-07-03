from django.shortcuts import render
from .forms import ContactForm
import os

refe=[]

def home(request):
    refe[:]=[]
    with open('summary.txt','w') as fs:
        fs.truncate()
    fs.close()
    with open('results.txt','w') as fs:
        fs.truncate()
    fs.close()
    if request.method=='POST':
        print(refe)
        form=ContactForm(request.POST)
        if form.is_valid():
            host=form.cleaned_data['host']
            console=form.cleaned_data['console']
            username=form.cleaned_data['username']
            password=form.cleaned_data['password']
            print(host,console,username,password)
            refe.append(host)
            refe.append(console)
            refe.append(username)
            refe.append(password)
    else :
        form=ContactForm()
    return render(request, 'blog/newhome.html',{'form':form})
def output(request):
    try:
        cmd = 'python ./blog/asr9k.py '+'-i '+refe[0]+' -c '+refe[1]+' -u '+refe[2]+' -p '+refe[3]
        print(cmd)
        os.system(cmd)
        with open('results.txt') as fs:
            data=fs.read()
        data = data.replace('\n', "<br />");
        fs.close()
        return render(request, 'blog/results.html', {'data':data})
    except:
        data = 'Sorry Error happened'
        return render(request, 'blog/results.html', {'data':data})
def summary(request):
    try:
        with open('summary.txt') as fs:
            data=fs.read()
        data = data.replace('\n', "<br />");
        fs.close()
        return render(request, 'blog/run.html', {'data':data})
    except:
        data = 'Sorry Error happened'
        return render(request, 'blog/run.html', {'data':data})
'''def logs(request):
    try:
        os.system('ssh bgl-ads-1534')
        os.system('Yhre321#78\n')
        cmd='cd /auto/tftp-blr-users1/ypandit/traces/'
        print(cmd)
        os.system(cmd)
        cmd='ls'
        os.system(cmd)
        cmd='exit'
        os.system(cmd)
        data='Hello'
        return render(request, 'blog/logs.html', {'data':data})
    except:
        data = 'Sorry Error happened'
        return render(request, 'blog/logs.html', {'data':data})'''
