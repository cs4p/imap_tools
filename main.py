#!/usr/bin/env python3

# To sanity check:
# flake8 --ignore E111,E114,E226,E265,E302,E305,E501

import sys
import argparse
import getpass
import ssl
import uuid
import logging
import pathlib
import imaplib
imaplib._MAXLINE = 10000000

logging.basicConfig(filename='imap_tools.log',
                    filemode='w',
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    level='DEBUG',
                    )

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler(sys.stdout))


def main():
    example = "Usage: %(prog)s -H imap.example.com -C ./cacert.pem -U user@example.com -P ./imap_pass -F inbox -S 'SINCE \"1-Jan-2020\"'"
    options = argparse.ArgumentParser(epilog=example)
    options.add_argument('-d', '--debug', help='Print debug messages', action='store_true')
    options.add_argument('-q', '--quiet', help="Don't print status messages", action='store_true')
    options.add_argument('-H', '--host', help='IMAP server hostname', required=True)
    options.add_argument('-P', '--port', help='IMAP server port (Default 993)', type=int, default=993)
    options.add_argument('-C', '--cafile', help='CA certificates file')
    options.add_argument('-u', '--user', help='IMAP username / email address', required=True)
    options.add_argument('-p', '--passfile', help='File containing IMAP password (Default is to prompt)')
    options.add_argument('-f', '--folder', help="IMAP folder to process")
    options.add_argument('-s', '--search', help='IMAP search filter; Defined in IMAP RFC 3501', default='ALL')
    options.add_argument('-l', '--limit', help='Limit the number of messages processed', type=int, default=0)
    options.add_argument('-o', '--output', help='output directory to write message files', default='messages')
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
    
    base_dir = pathlib.Path(__file__).parent.resolve()
    msg_dir = base_dir.joinpath(args.output)
    ret = setup_msg_folder(msg_dir)
    if ret != 0:
        logger.debug("Error creating output folder %s" % msg_dir)
        sys.exit()
    else:
        logger.debug("Output folder is %s..." % msg_dir)
    
    imap = imap_login(args.host, args.port, sc, args.user, args.passwd)
    
    # ret = process_folder(imap, args.folder, args.output, args.search, args.limit)
    ret = list_folders(imap, msg_dir, args.folder, args.search, args.limit)
    
    logger.debug('Closing folder and logging out ...')
    imap.close()
    imap.logout()
    sys.exit(ret)


def imap_login(host, port, sc, user, passwd):
    logger.debug("Connecting to IMAP server on %s port %s ..." % (host, port))
    imap = imaplib.IMAP4_SSL(host, port, ssl_context=sc)
    imap.login(user, passwd)
    return imap


def list_folders(imap, msg_dir: pathlib.Path, folder=None, search='ALL', limit=None):
    if folder is None:
        logger.debug("Listing root folders...")
        ret, folder_list = imap.list()
    else:
        logger.debug("Listing %s child folders..." % folder)
        ret, folder_list = imap.list(folder)
    for folder in folder_list:
        folder = folder.decode()
        folder_name = folder[folder.rfind('"/"') + 2:].replace('"', '').strip()
        folder_msg_dir = msg_dir.joinpath(folder_name)
        setup_msg_folder(folder_msg_dir)
        process_folder(imap, folder_name, folder_msg_dir, search, limit)
    
    return 0


def process_folder(imap, folder, msg_dir, search='ALL', limit=None):
    if limit == 0:
        limit = None
    logger.debug("Selecting folder '%s' ..." % folder)
    logger.debug("Folder = %s" % folder)
    ret, data = imap.select('"' + folder + '"')
    if ret != 'OK':
        logger.error("Error opening folder '%s': %s" % (folder, data))
        imap.logout()
        sys.exit(10)
    num_of_messages = data[0].decode()
    
    if num_of_messages == '0':
        logger.info('No messages found')
        return 0
    else:
        logger.debug("Folder contains %s messages" % num_of_messages)
        
    logger.debug("Searching for messages matching '%s' ..." % search)
    ret, data = imap.search(None, '(' + search + ')')

    if ret != 'OK':
        logger.info('No messages found')
        return 0
    msg_nums = data[0].split()
    logger.debug("Found %s messages" % len(msg_nums))
    
    count = len(msg_nums)
    if limit and count > limit:
        logger.debug("Processing %s messages (limited per '--limit' argument) ..." % limit)
    else:
        logger.debug("Processing %s messages ..." % count)
    
    count = ret = 0
    for msg_num in reversed(msg_nums):
        msg_ret = process_message(imap, msg_num, msg_dir)
        if msg_ret != 0 and ret == 0:
            ret = msg_ret
        if limit:
            count += 1
            if count >= limit:
                break
    return ret


def process_message(imap, msg_num, msg_dir):
    logger.debug("Fetching message %s ..." % msg_num.decode())
    ret, data = imap.fetch(msg_num, '(RFC822)')
    if ret != 'OK':
        logger.error("Error fetching message %s : %s" % (msg_num.decode(), data))
        return 11
    
    # TODO - Do something with message data here
    file_name = '.'.join([uuid.uuid4().__str__(), 'msg'])
    msg_file = open(msg_dir.joinpath(file_name), 'wb')
    msg_file.write(data[0][1])
    msg_file.close()
    
    return 0


def setup_msg_folder(msg_dir):
    if not pathlib.Path.exists(msg_dir):
        pathlib.Path.mkdir(msg_dir)
    return 0


if __name__ == "__main__":
    main()
