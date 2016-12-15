from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader


import re
import logging
import socket
import smtplib
import DNS
import threading

class myThread (threading.Thread):
    def __init__(self, email, hosts, valid_emails):
        threading.Thread.__init__(self)
        self.email = email
        self.hosts = hosts
        self.valid_emails = valid_emails
    def run(self):
        if validate_email(self.email, self.hosts, debug=False, smtp_timeout=10):
            self.valid_emails.append(self.email)

WSP = r'[\s]'                                        # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'                                   # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'        # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'                             # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + \
      WSP + r'+)'                                    # see 3.2.3. Folding white space and comments
CTEXT = r'[' + NO_WS_CTL + \
        r'\x21-\x27\x2a-\x5b\x5d-\x7e]'              # see 3.2.3
CCONTENT = r'(?:' + CTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.2.3 (NB: The RFC includes COMMENT here
# as well, but that would be circular.)
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + \
          r')*' + FWS + r'?\)'                       # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + \
       FWS + '?' + COMMENT + '|' + FWS + ')'         # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'           # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'      # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'   # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?' # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + \
        r'\x21\x23-\x5b\x5d-\x7e]'                   # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + \
                r'?' + QCONTENT + r')*' + FWS + \
                r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + \
             QUOTED_STRING + r')'                    # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'    # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + \
                 r'(?:' + FWS + r'?' + DCONTENT + \
                 r')*' + FWS + r'?\]' + CFWS + r'?'  # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + \
         DOMAIN_LITERAL + r')'                       # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN               # see 3.4.1

# A valid address will match exactly the 3.4.1 addr-spec.
VALID_ADDRESS_REGEXP = '^' + ADDR_SPEC + '$'

MX_DNS_CACHE = {}
MX_CHECK_CACHE = {}


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


def get_host_ip(domain):
    DNS.DiscoverNameServers()
    # Perform mxlookup for domain
    mx_hosts = DNS.mxlookup(domain)
    for mx in mx_hosts:
        smtp = smtplib.SMTP()
        # if this doesn't raise an exception it is a valid MX host...
        try:
            smtp.connect(mx[1])
        except smtplib.SMTPConnectError:
            mx_hosts.remove(mx)
            continue  # try the next MX server in list
    return mx_hosts

def get_host_ip2(domain):
    DNS.DiscoverNameServers()
    # Perform mxlookup for domain
    mx_hosts = DNS.mxlookup(domain)
    for mx in mx_hosts:
        smtp = smtplib.SMTP()
        # if this doesn't raise an exception it is a valid MX host...
        try:
            smtp.connect(mx[1])
        except smtplib.SMTPConnectError:
            mx_hosts.remove(mx)
            continue  # try the next MX server in list
    return mx_hosts


def validate_email(email, mx_hosts, debug=False, smtp_timeout=10):
    if debug:
        logger = logging.getLogger('validate_email')
        logger.setLevel(logging.DEBUG)
    else:
        logger = None

    try:
        assert re.match(VALID_ADDRESS_REGEXP, email) is not None
        if mx_hosts is None:
            return False
        if not DNS:
            raise Exception('For check the mx records or check if the email exists you must '
                                'have installed pyDNS python package')
        hostname = email[email.find('@') + 1:]

        if mx_hosts is None:
            return False
        for mx in sorted(mx_hosts):
            smtp = smtplib.SMTP(timeout=smtp_timeout)
            smtp.connect(mx[1])
            status, _ = smtp.helo()
            if status != 250:
                smtp.quit()
                if debug:
                    logger.debug(u'%s answer: %s - %s', mx[1], status, _)
                continue
            smtp.mail('')
            status, _ = smtp.rcpt(email)
            if status == 250:
                print(email+' is valid')
                smtp.quit()
                return True

    except AssertionError:
        return False
    except Exception as e:
        if debug:
            logger.debug('Exception raised (%s).', e)
        return None
    return False


def hello(request):
   context= {}
   template = loader.get_template('hello.html')
   return HttpResponse(template.render(context, request))


def hello2(request):
   text="<h1>hello</h1>"+request.POST.get('name')+request.POST.get('lname')+request.POST.get('dname')
   fn=request.POST.get('name')
   ln=request.POST.get('lname')
   dn=request.POST.get('dname')
   logging.basicConfig()
   email_list = get_email_list(fn,ln,dn)
   hosts = get_host_ip(dn)
   valid_emails = []
   threads = []
   for email in email_list:
      threads.append(myThread(email,hosts,valid_emails))
   for t in threads:
      t.start()
   for t in threads:
      t.join()
   text2="<h2>Results !</h2>"
   for x in valid_emails:
   		print(x)
   		text2=text2+"<h5>"+x+"</h5>";
   return HttpResponse(text2)