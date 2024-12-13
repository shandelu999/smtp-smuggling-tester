from colorama import Style
from colorama import Fore
import dns.resolver
import email.utils
import argparse
import datetime
import smtplib
import socket

smtp_connection_timeout = 5
current_server_replies = []

# 为了减少误报，目前已减少了入站测试的结束序列(https://github.com/The-Login/SMTP-Smuggling-Tools/issues/6)
inbound_eod_sequences = [
    "\n.\n",
    "\n.\r",
    "\r.\n",
    "\r.\r",
    "\n.\r\n",
    "\r.\r\n",
    "\r\n\x00.\r\n"
]

outbound_eod_sequences = [
    "\n.\n",
    "\n.\r",
    "\r.\n",
    "\r.\r",
    "\n.\r\n",
    "\r.\r\n",
    "\r\n.\r\r\n",
    "\r\r\n.\r\r\n",
    "\r\n\x00.\r\n"
]

examples = """命令：
扫描入站 SMTP 服务器命令：
  python3 smtp-smuggling-tester.py --setup-check YOUR@EMAIL.ADDRESS
  python3 smtp-smuggling-tester.py YOUR@EMAIL.ADDRESS
扫描出站 SMTP 服务器命令：
  python3 smtp-smuggling-tester.py YOUR@RECEIVER.ADDRESS --outbound-smtp-server SOMESERVER.SMTP.SERVER --port 587 --starttls --sender-address YOUR@EMAIL.ADRESS --username YOUR@EMAIL.ADRESS --password PASSWORD --setup-check
  python3 smtp-smuggling-tester.py YOUR@RECEIVER.ADDRESS --outbound-smtp-server SOMESERVER.SMTP.SERVER --port 587 --starttls --sender-address YOUR@EMAIL.ADRESS --username YOUR@EMAIL.ADRESS --password PASSWORD
"""

class out:
    def green(self, msg):
        print(Fore.GREEN + msg + Style.RESET_ALL)

    def blue(self, msg):
        print(Fore.BLUE + msg + Style.RESET_ALL)

    def cyan(self, msg):
        print(Fore.CYAN + msg + Style.RESET_ALL)

    def red(self, msg):
        print(Fore.RED + msg + Style.RESET_ALL)

    def yellow(self, msg):
        print(Fore.YELLOW + msg + Style.RESET_ALL)

    def magenta(self, msg):
        print(Fore.MAGENTA + msg + Style.RESET_ALL)

    def alert(self, msg):
        print(Fore.RED + "[!] " + msg + Style.RESET_ALL)

    def info(self, msg):
        print(Fore.BLUE + "[*] " + msg + Style.RESET_ALL)

    def success(self, msg):
        print(Fore.GREEN + "[+] " + msg + Style.RESET_ALL)
    
    def debug(self, msg):
        if debug:
            print(Fore.CYAN + "[DEBUG] " + msg + Style.RESET_ALL)

# 改编自以下 github 代码：https://github.com/python/cpython/blob/main/Lib/smtplib.py#L82
def new_getreply(self):
    global current_server_replies
    resp = []
    if self.file is None:
        self.file = self.sock.makefile('rb')
    while 1:
        try:
            line = self.file.readline(smtplib._MAXLINE + 1)
        except OSError as e:
            self.close()
            raise smtplib.SMTPServerDisconnected("Connection unexpectedly closed: " + str(e))
        if not line:
            self.close()
            raise smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
        if self.debuglevel > 0:
            self._print_debug('reply:', repr(line))
        if len(line) > smtplib._MAXLINE:
            self.close()
            raise smtplib.SMTPResponseException(500, "Line too long.")
        resp.append(line[4:].strip(b' \t\r\n'))
        code = line[:3]
        # 检查错误代码的语法是否正确。
        # 如果续行已断，请勿尝试读取。
        try:
            errcode = int(code)
        except ValueError:
            errcode = -1
            break
        # 检查是否为多行响应。
        if line[3:4] != b"-":
            break

    errmsg = b"\n".join(resp)
    if self.debuglevel > 0:
        current_server_replies.append({"code": errcode, "message": errmsg.decode()})
        self._print_debug('reply: retcode (%s); Msg: %a' % (errcode, errmsg))
    return errcode, errmsg

# 调整 smtplib 的数据处理方式
def new_data(self, msg):
        self.putcmd("data")

        (code, repl) = self.getreply()
        if self.debuglevel > 0:
            self._print_debug('data:', (code, repl))
        if code != 354:
            raise SMTPDataError(code, repl)
        else:
            # 这里注释的代码块，如果启用，可用于发送 data 邮件内容
            #if isinstance(msg, str):
            #    msg = smtplib._fix_eols(msg).encode('ascii')
            #q = smtplib._quote_periods(msg)
            #if q[-2:] != smtplib.bCRLF:
            #    q = q + smtplib.bCRLF
            #q = q + b"." + smtplib.bCRLF
            q = msg
            self.send(q)
            (code, msg) = self.getreply()
            if self.debuglevel > 0:
                self._print_debug('data:', (code, msg))
            return (code, msg)

# 用于绕过 smtplib 中的某些功能
def return_unchanged(data):
    return data

# 通过发送测试电子邮件检查所用的入站扫描测试设置
def check_inbound_setup(inbound_smtp_server, sender_domain, receiver_address, tls, starttls, port):
    global current_server_replies
    current_server_replies = []
    try:
        if tls:
            server = smtplib.SMTP_SSL(inbound_smtp_server, port, timeout=smtp_connection_timeout)
        else:
            server = smtplib.SMTP(inbound_smtp_server, port, timeout=smtp_connection_timeout)

        if debug:
            server.set_debuglevel(1)

        if not tls and starttls:
            server.starttls()

        mail_date = email.utils.format_datetime(datetime.datetime.now())
        message_id = email.utils.make_msgid(domain=sender_domain)
        server.ehlo(sender_domain)
        sender_address = f"setup_check@{sender_domain}"
        check_message = """\
From: {sender_address}
To: {receiver_address}
Subject: SETUP CHECK
Date: {mail_date}
Message-ID: {message_id}

您的入站设置正在运行！您现在可以继续进行走私测试了！
.
"""
        check_message = _fix_eols(check_message)
        check_message = check_message.format(sender_address=sender_address, receiver_address=receiver_address, mail_date=mail_date, message_id=message_id)
        server.sendmail(sender_address, [receiver_address], check_message)
        out.success("已发送设置电子邮件！请检查您的收件箱！")
        while True:
            server.getreply()

    except socket.error:
        for reply in enumerate(current_server_replies):
            out.debug(str(reply))
        pass
        return True
    except Exception as e:
        out.debug(str(e))
        try:
            server.quit()
            return True
        except Exception as e:
            pass
            return True

# 通过发送测试电子邮件检查用于出站扫描的测试设置
def check_outbound_setup(outbound_smtp_server, sender_address, receiver_address, username, password, smuggling_identifier, tls, starttls, port):
    global current_server_replies
    current_server_replies = []
    try:
        if tls:
            server = smtplib.SMTP_SSL(outbound_smtp_server, port, timeout=smtp_connection_timeout)
        else:
            server = smtplib.SMTP(outbound_smtp_server, port, timeout=smtp_connection_timeout)
        
        if debug:
            server.set_debuglevel(1)

        if not tls and starttls:
            server.starttls()

        if username != False and password != False:
            server.login(username, password)

        check_message = """\
From: {sender_address}
To: {receiver_address}
Subject: SETUP CHECK

{smuggling_identifier_start}
您的出站设置似乎正在运行！您现在可以继续进行走私测试了！
{smuggling_identifier_end}
.
"""
        check_message = _fix_eols(check_message)
        check_message = check_message.format(sender_address=sender_address, receiver_address=receiver_address,  smuggling_identifier_start=smuggling_identifier + "START", smuggling_identifier_end=smuggling_identifier + "END")
        server.sendmail(sender_address, [receiver_address], check_message)
        out.success("已发送设置电子邮件！请检查您的收件箱！")
        while True:
            server.getreply()

    except socket.error:
        for reply in enumerate(current_server_replies):
            out.debug(str(reply))
        pass
        return True
    except Exception as e:
        out.debug(str(e))
        try:
            server.quit()
            return True
        except Exception as e:
            pass
            return True

# 使用一系列不符合 RFC 的数据结束序列执行多个入站 SMTP 走私检查
def check_inbound_smuggling(inbound_smtp_server, sender_domain, receiver_address, tls, starttls, port):

    for eod_sequence in inbound_eod_sequences:
        global current_server_replies
        current_server_replies = []
        eod_sequence_string = repr(eod_sequence)
        try:
            if tls:
                server = smtplib.SMTP_SSL(inbound_smtp_server, port, timeout=smtp_connection_timeout)
            else:
                server = smtplib.SMTP(inbound_smtp_server, port, timeout=smtp_connection_timeout)

            if debug:
                server.set_debuglevel(1)

            if not tls and starttls:
                server.starttls()

            mail_date = email.utils.format_datetime(datetime.datetime.now())
            message_id = email.utils.make_msgid(domain=sender_domain)
            message_id2 = email.utils.make_msgid(domain=sender_domain)
            server.ehlo(sender_domain)
            sender_address = f"test@{sender_domain}"
            sender_address_smuggled = f"smuggled@{sender_domain}"
            check_message = """\
From: {sender_address}
To: {receiver_address}
Subject: CHECK EMAIL ({eod_sequence_string})
Date: {mail_date}
Message-ID: {message_id}

测试 {eod_sequence_string} 作为“假”数据结束序列！
{inject}
mail FROM:<{sender_address_smuggled}>
rcpt TO:<{receiver_address}>
data
From: {sender_address_smuggled}
To: {receiver_address}
Subject: SMUGGLED EMAIL ({eod_sequence_string})
Date: {mail_date}
Message-ID: {message_id2}

走私可以工作从以下 {eod_sequence_string} 作为“假”数据结束序列！
.
"""
            check_message = _fix_eols(check_message)
            check_message = check_message.format(inject=eod_sequence, eod_sequence_string=eod_sequence_string, sender_address=sender_address, sender_address_smuggled=sender_address_smuggled, receiver_address=receiver_address, mail_date=mail_date, message_id=message_id, message_id2=message_id2)
            server.sendmail(sender_address, [receiver_address], check_message)
            out.success(f"发送走私电子邮件以结束数据序列 {eod_sequence_string}! 检查您的收件箱！")
            while True:
                server.getreply()

        except socket.error as e:
            out.debug(str(e))
            for reply in enumerate(current_server_replies):
                out.debug(str(reply))

            pass
            continue
        except Exception as e:
            out.debug(str(e))
            try:
                server.quit()
                continue
            except Exception as e:
                pass
                continue

# 使用一系列不符合 RFC 的数据结束序列执行多个出站 SMTP 走私检查
def check_outbound_smuggling(outbound_smtp_server, sender_address, receiver_address, username, password, smuggling_identifier, tls, starttls, port):
        
    for eod_sequence in outbound_eod_sequences:
        global current_server_replies
        current_server_replies = []
        eod_sequence_string = repr(eod_sequence)
        try:
            if tls:
                server = smtplib.SMTP_SSL(outbound_smtp_server, port, timeout=smtp_connection_timeout)
            else:
                server = smtplib.SMTP(outbound_smtp_server, port, timeout=smtp_connection_timeout)
            
            if debug:
                server.set_debuglevel(1)

            if not tls and starttls:
                server.starttls()

            if username != False and password != False:
                server.login(username, password)

            check_message = """\
From: {sender_address}
To: {receiver_address}
Subject: Trying EOD ({eod_sequence_string})

测试 {eod_sequence_string} 作为“假”数据结束序列！
{smuggling_identifier_start}
{inject}
{smuggling_identifier_end}
.
"""
            check_message = _fix_eols(check_message)
            check_message = check_message.format(sender_address=sender_address, receiver_address=receiver_address, eod_sequence_string=eod_sequence_string, smuggling_identifier_start=smuggling_identifier + "START", inject=eod_sequence, smuggling_identifier_end=smuggling_identifier + "END")
            server.sendmail(sender_address, [receiver_address], check_message)
            out.success(f"发送走私电子邮件以结束数据序列 {eod_sequence_string}! 检查您的收件箱！")
            while True:
                server.getreply()

        except socket.error:
            for reply in enumerate(current_server_replies):
                out.debug(str(reply))
            pass
            continue
        except Exception as e:
            out.debug(str(e))
            try:
                server.quit()
                continue
            except Exception as e:
                pass
                continue

if __name__ == '__main__':
    _fix_eols = smtplib._fix_eols
    smtplib._fix_eols = return_unchanged
    smtplib._quote_periods = return_unchanged
    smtplib.SMTP.data = new_data
    smtplib.SMTP.getreply = new_getreply
    out = out()
    
    # 帮助
    argument_parser = argparse.ArgumentParser(prog="smtp-smuggling-tester", description="用于查找入站/接收和出站/发送 SMTP 服务器中的 SMTP 走私问题的工具。", epilog=examples, formatter_class=argparse.RawDescriptionHelpFormatter)
    argument_parser.add_argument("--receiver_address", help="要使用的接收方地址。请确保这是一个有效的电子邮件地址。", nargs=1)
    argument_parser.add_argument("--sender-domain", help="要使用的发件人域。请确保您拥有此域的有效 SPF 记录。",default="检查：smtpsmuggling.com")
    argument_parser.add_argument("--inbound-smtp-server", help="手动指定要检查的接收/入站 SMTP 服务器。", default=False)
    argument_parser.add_argument("--outbound-smtp-server", help="要使用的出站 SMTP 服务器（邮件提交代理）的地址。", default="")
    argument_parser.add_argument("--sender-address", help="要使用的（出站）发件人地址。",default="")
    argument_parser.add_argument("--username", help="用于（出站）身份验证的用户名。", default=False)
    argument_parser.add_argument("--password", help="用于（出站）身份验证的密码。", default=False)
    argument_parser.add_argument("--smuggling-identifier", help="用于在接收 SMTP 分析服务器上突出显示的标识符。", default="走私")
    argument_parser.add_argument("--setup-check", help="通过发送测试电子邮件检查您的设置是否正常运行。", action="设置正确")
    argument_parser.add_argument("--tls", help="强制使用 TLS。（不要忘记更改端口！）", action="设置正确")
    argument_parser.add_argument("--starttls", help="强制使用 STARTTLS。（通常需要发送出站电子邮件）", action="设置正确")
    argument_parser.add_argument("--debug", help="输出调试信息。", action="设置正确")
    argument_parser.add_argument("-p", "--port", help="要使用的端口。", type=int, default=25)
    args = argument_parser.parse_args()
    debug = args.debug

    receiver_domain = args.receiver_address[0].split("@")[1]

    if args.inbound_smtp_server == False and not args.outbound_smtp_server:
        out.info(f"获取域名的 MX 记录: {receiver_domain}")
        try:
            inbound_smtp_server = str(dns.resolver.resolve(receiver_domain, 'MX')[0].exchange)
        except Exception as e:
            out.alert(f"未找到域名的 MX 记录 {receiver_domain}! 这是一个有效的接收方域名吗？")
            quit()
    elif args.inbound_smtp_server:
        inbound_smtp_server = args.inbound_smtp_server

    if args.setup_check and not args.outbound_smtp_server:
        out.info("正在运行入站设置检查！")
        check_inbound_setup(inbound_smtp_server, args.sender_domain, args.receiver_address[0], args.tls, args.starttls, args.port)
    elif not args.setup_check and not args.outbound_smtp_server:
        out.info("正在运行入站 SMTP 走私检查！")
        check_inbound_smuggling(inbound_smtp_server, args.sender_domain, args.receiver_address[0], args.tls, args.starttls, args.port)
    elif args.setup_check and args.outbound_smtp_server:
        out.info("正在运行出站设置检查！")
        check_outbound_setup(args.outbound_smtp_server, args.sender_address, args.receiver_address[0], args.username, args.password, args.smuggling_identifier, args.tls, args.starttls, args.port)
    elif not args.setup_check and args.outbound_smtp_server:
        out.info("正在运行出站 SMTP 走私检查！")
        check_outbound_smuggling(args.outbound_smtp_server, args.sender_address, args.receiver_address[0], args.username, args.password, args.smuggling_identifier, args.tls, args.starttls, args.port)
