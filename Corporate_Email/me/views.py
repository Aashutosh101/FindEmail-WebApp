from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader


import threading

from validate_email import validate_email
class myThread (threading.Thread):
    def __init__(self, email, valid_emails):
        threading.Thread.__init__(self)
        self.email = email
        self.valid_emails = valid_emails
    def run(self):
        if validate_email(self.email,verify=True):
            self.valid_emails.append(self.email)



def get_email_list(fn, ln, dn):
    list = [ fn+"@"+dn ]
    list.append(ln+"@"+dn)
    list.append(fn+ln+"@"+dn)
    list.append(fn+"."+ln+"@"+dn)
    list.append(fn[0]+ln+"@"+dn)
    list.append(fn[0]+"."+ln+"@"+dn)
    list.append(fn+ln[0]+"@"+dn)
    list.append(fn+"."+ln[0]+"@"+dn)
    list.append(fn[0]+ln[0]+"@"+dn)
    list.append(fn[0]+"."+ln[0]+"@"+dn)
    list.append(ln+fn+"@"+dn)
    list.append(ln+"."+fn+"@"+dn)
    list.append(ln+fn[0]+"@"+dn)
    list.append(ln+"."+fn[0]+"@"+dn)
    list.append(ln[0]+fn+"@"+dn)
    list.append(ln[0]+"."+fn+"@"+dn)
    list.append(ln[0]+fn[0]+"@"+dn)
    list.append(ln[0]+"."+fn[0]+"@"+dn)
    list.append(fn+"-"+ln+"@"+dn)
    list.append(fn[0]+"-"+ln+"@"+dn)
    list.append(fn+"-"+ln[0]+"@"+dn)
    list.append(fn[0]+"-"+ln[0]+"@"+dn)
    list.append(ln+"-"+fn+"@"+dn)
    list.append(ln+"-"+fn[0]+"@"+dn)
    list.append(ln[0]+"-"+fn+"@"+dn)
    list.append(ln[0]+"-"+fn[0]+"@"+dn)
    list.append(fn+"_"+ln+"@"+dn)
    list.append(fn[0]+"_"+ln+"@"+dn)
    list.append(fn+"_"+ln[0]+"@"+dn)
    list.append(fn[0]+"_"+ln[0]+"@"+dn)
    list.append(ln+"_"+fn+"@"+dn)
    list.append(ln+"_"+fn[0]+"@"+dn)
    list.append(ln[0]+"_"+fn+"@"+dn)
    list.append(ln[0]+"_"+fn[0]+"@"+dn)
    return list


def hello(request):
   context= {}
   template = loader.get_template('hello.html')
   return HttpResponse(template.render(context, request))

def hello2(request):
   text="<h1>hello</h1>"+request.POST.get('name')+request.POST.get('lname')+request.POST.get('dname')
   fn=request.POST.get('name')
   ln=request.POST.get('lname')
   dn=request.POST.get('dname')
   email_list = get_email_list(fn,ln,dn)
   valid_emails = []
   threads = []
   for email in email_list:
      threads.append(myThread(email, valid_emails))
   for t in threads:
      t.start()
   for t in threads:
      t.join()
   text2="<h2>Results !</h2>"
   for x in valid_emails:
   		print(x)
   		text2=text2+"<h5>"+x+"</h5>";
   return HttpResponse(text2)