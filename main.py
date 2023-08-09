#!/usr/bin/env python3

# To sanity check:
# flake8 --ignore E111,E114,E226,E265,E302,E305,E501

import sys
import argparse
import getpass
import ssl
import imaplib

import logging

logging.basicConfig(filename='imap_tools.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s',
                    level='DEBUG')


def main():
    global args
    example = "Usage: %(prog)s -H imap.example.com -C ./cacert.pem -U user@example.com -P ./imap_pass -F inbox -S 'SINCE \"1-Jan-2020\"'"
    options = argparse.ArgumentParser(epilog=example)
    options.add_argument('-d', '--debug', help='Print debug messages', action='store_true')
    options.add_argument('-q', '--quiet', help="Don't print status messages", action='store_true')
    options.add_argument('-H', '--host', help='IMAP server hostname', required=True)
    options.add_argument('-P', '--port', help='IMAP server port (Default 993)', type=int, default=993)
    options.add_argument('-C', '--cafile', help='CA certificates file')
    options.add_argument('-u', '--user', help='IMAP username / email address', required=True)
    options.add_argument('-p', '--passfile', help='File containing IMAP password (Default is to prompt)')
    options.add_argument('-f', '--folder', help="IMAP folder to process (Default 'INBOX')", default='INBOX')
    options.add_argument('-s', '--search', help='IMAP search filter; Defined in IMAP RFC 3501', default='ALL')
    options.add_argument('-l', '--limit', help='Limit the number of messages processed', type=int, default=0)
    args = options.parse_args()

    if args.passfile:
        with open(args.passfile) as f:
            args.passwd = f.readline().strip()
    else:
        args.passwd = getpass.getpass()

    sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sc.minimum_version = ssl.TLSVersion.TLSv1_2
    if args.cafile:
        sc.load_verify_locations(cafile=args.cafile)
    else:
        sc.set_default_verify_paths()
    # sc.check_hostname = False

    imap = imap_login(args.host, args.port, sc, args.user, args.passwd)

    ret = process_folder(imap, args.folder, args.search, args.limit)

    logging.debug('Closing folder and logging out ...')
    imap.close()
    imap.logout()
    sys.exit(ret)


def imap_login(host, port, sc, user, passwd):
    logging.debug("Connecting to IMAP server on %s port %s ..." % (host, port))
    imap = imaplib.IMAP4_SSL(host, port, ssl_context=sc)
    imap.login(user, passwd)
    return imap


def list_folders(imap, search='ALL', limit=0, folder=''):
    logging.debug("Listing root folders...")
    ret, data = imap.list()
    folder_list = data
    for folder in folder_list:
        has_children = folder[2:folder.find(' \\')]
        folder_name = folder[folder.find(' \\') + 2:folder.find(')')]
        process_folder(imap, folder_name, search, limit)


def process_folder(imap, folder, search='ALL', limit=0):
    logging.debug("Selecting folder '%s' ..." % folder)
    ret, data = imap.select(folder)
    if ret != 'OK':
        logging.error("Error opening folder '%s': %s" % (folder, data))
        imap.logout()
        sys.exit(10)
    logging.debug("Folder contains %s messages" % data[0].decode())

    logging.debug("Searching for messages matching '%s' ..." % search)
    ret, data = imap.search(None, '(' + search + ')')
    if ret != 'OK':
        logging.info('No messages found')
        return 0
    msg_nums = data[0].split()
    logging.debug("Found %s messages" % len(msg_nums))

    count = len(msg_nums)
    if limit and count > limit:
        logging.debug("Processing %s messages (limited per '--limit' argument) ..." % limit)
    else:
        logging.debug("Processing %s messages ..." % count)

    count = ret = 0
    for msg_num in reversed(msg_nums):
        msg_ret = process_message(imap, msg_num)
        if msg_ret != 0 and ret == 0:
            ret = msg_ret
        if limit:
            count += 1
        if count >= limit:
            break
    return ret


def process_message(imap, msg_num):
    logging.debug("Fetching message %s ..." % msg_num.decode())
    ret, data = imap.fetch(msg_num, '(RFC822)')
    if ret != 'OK':
        logging.error("Error fetching message %s : %s" % (msg_num.decode(), data))
        return 11

    # TODO - Do something with message data here
    print(data)

    return 0


if __name__ == "__main__":
    main()
