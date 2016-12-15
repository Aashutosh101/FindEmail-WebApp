# RFC 2822 - style email validation for Python
# (c) 2012 Syrus Akbary <me@syrusakbary.com>
# Extended from (c) 2011 Noel Bush <noel@aitools.org>
# for support of mx and user check
# This code is made available to you under the GNU LGPL v3.
#
# This module provides a single method, valid_email_address(),
# which returns True or False to indicate whether a given address
# is valid according to the 'addr-spec' part of the specification
# given in RFC 2822.  Ideally, we would like to find this
# in some other library, already thoroughly tested and well-
# maintained.  The standard Python library email.utils
# contains a parse_addr() function, but it is not sufficient
# to detect many malformed addresses.
#
# This implementation aims to be faithful to the RFC, with the
# exception of a circular definition (see comments below), and
# with the omission of the pattern components marked as "obsolete".
import re
import logging
import socket
import smtplib

try:
    import DNS
    ServerError = DNS.ServerError
    DNS.DiscoverNameServers()
except (ImportError, AttributeError):
    DNS = None

    class ServerError(Exception):
        pass

# All we are really doing is comparing the input string to one
# gigantic regular expression.  But building that regexp, and
# ensuring its correctness, is made much easier by assembling it
# from the "tokens" defined by the RFC.  Each of these tokens is
# tested in the accompanying unit test file.
#
# The section of RFC 2822 from which each pattern component is
# derived is given in an accompanying comment.
#
# (To make things simple, every string below is given as 'raw',
# even when it's not strictly necessary.  This way we don't forget
# when it is necessary.)
#
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


def validate_email(email, mx_hosts, debug=False, smtp_timeout=10):
    """Indicate whether the given string is a valid email address
    according to the 'addr-spec' portion of RFC 2822 (see section
    3.4.1).  Parts of the spec that are marked obsolete are *not*
    included in this test, and certain arcane constructions that
    depend on circular definitions in the spec may not pass, but in
    general this should correctly identify any email address likely
    to be in use as of 2011."""
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
    except (ServerError, socket.error) as e:
        if debug:
            logger.debug('ServerError or socket.error exception raised (%s).', e)
        return None
    return False


if __name__ == "__main__":
    fn = raw_input('First name: ')
    ln = raw_input('Last name: ')
    dn = raw_input('Domain: ')

    logging.basicConfig()
    email_list = get_email_list(fn, ln, dn)
    hosts = get_host_ip(dn)
    valid_emails = []
    for email in email_list:
        print('checking ' + email)
        result = validate_email(email, hosts, debug=False, smtp_timeout=10)
        if result:
            valid_emails.append(email)

    for x in valid_emails:
        print(x)

