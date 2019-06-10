from django.shortcuts import render
from .forms import ContactForm
import os

refe=[]

def home(request):
    refe[:]=[]
    with open('summary.txt','w') as fs:
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
    return render(request, 'blog/home.html',{'form':form})
def output(request):
    cmd = 'python ./blog/pyth.py '+refe[0]+' '+refe[1]+' '+refe[2]+' '+refe[3]
    print(cmd)
    os.system(cmd)
    with open('summary.txt') as fs:
        data=fs.read()
    data = data.replace('\n', "<br />");
    fs.close()
    return render(request, 'blog/run.html', {'data':data})
