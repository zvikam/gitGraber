#!/usr/bin/python3

import requests
import re
import json
import time
import argparse
import mmap
import argcomplete
import config
import glob
import tokens
import os
import time
import urllib.parse
from functools import partial
from datetime import datetime
from pprint import pprint
from termcolor import colored
from urllib.parse import urlparse
from multiprocessing.dummy import Pool
from crontab import CronTab


def createEmptyBinaryFile(name):
    f = open(name, 'wb')
    f.write(1*b'\0')
    f.close()


def initFile(name):
    if not name or not os.path.exists(name) or os.path.getsize(name) == 0:
        createEmptyBinaryFile(name)


def clean(result):
    cleanToken = re.sub(tokens.CLEAN_TOKEN_STEP1, '', result.group(0))
    return re.sub(tokens.CLEAN_TOKEN_STEP2, '', cleanToken)


def checkToken(content, tokensMap, tokensCombo):
    tokensFound = {}
    # For each type of tokens (ie 'AWS'...)
    for token in tokensMap:
        regexPattern = re.compile(token.getRegex())
        # Apply the matching regex on the content of the file
        result = re.search(regexPattern, content)
        # If the regex matches, add the result of the match to the dict tokens and the token name found
        if result:
            cleanToken = clean(result) 
            blacklist = token.getBlacklist()
            foundbl = False
            if blacklist:
                for blacklistedPattern in blacklist:
                    if blacklistedPattern in cleanToken:
                        foundbl = True
            if not foundbl:
                tokensFound[cleanToken] = token.getName()
    
    for combo in tokensCombo:
        found = True
        result = [''] * len(combo.getTokens())
        for t in combo.getTokens():
            regexPattern = re.compile(t.getRegex())
            match = re.search(regexPattern, content)
            if not match:
                found = False
                break
            result[t.getDisplayOrder()-1] = clean(match)
        if found:
            concatToken = ":".join(result)
            tokensFound[concatToken] = combo.getName()

    return tokensFound


def notifySlack(message):
    if not config.SLACK_WEBHOOKURL:
        print('Please define Slack Webhook URL to enable notifications')
        exit()
    requests.post(config.SLACK_WEBHOOKURL, json={'text': ':new:'+message})


def notifyTelegram(message):
    if not config.TELEGRAM_CONFIG or not config.TELEGRAM_CONFIG.get("token") or not config.TELEGRAM_CONFIG.get("chat_id"):
        print('Please define Telegram config to enable notifications')
        exit()

    telegramUrl = "https://api.telegram.org/bot{}/sendMessage".format(config.TELEGRAM_CONFIG.get("token"))
    requests.post(telegramUrl, json={'text': message, 'chat_id': config.TELEGRAM_CONFIG.get("chat_id")})


def writeToWordlist(content, wordlist):
    f = open(wordlist, 'a+')
    s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    filename = content.split('/')[-1]
    if s.find(bytes(filename,'utf-8')) == -1:
        f.write(filename + '\n')


def displayResults(result, tokenResult, filename):
    possibleTokenString = '[!] POSSIBLE ' + tokenResult[result] + ' TOKEN FOUND'
    print(colored(possibleTokenString,'green'))
    pathString = '[+] FILE : ' + filename
    print(pathString)
    tokenString = '[+] Token : ' + result 
    print(tokenString.strip())
    return possibleTokenString+'\n'+pathString+'\n'+tokenString


def doSearchFilesystem(args, tokenMap, tokenCombos, file):
    try:
        with open(file, 'r') as f:
            content = f.read()
    except:
        if args.verbose:
            print("[+] skipping binary file", file)
        return
    if args.verbose:
        print("[+] checking", file)
    tokensResult = checkToken(content, tokenMap, tokenCombos)
    for token in tokensResult.keys():
        displayMessage = displayResults(token, tokensResult, file)
        if args.slack:
            notifySlack(displayMessage)
        if args.telegram:
            notifyTelegram(displayMessage)
        if args.wordlist:
            writeToWordlist(file, args.wordlist)


def findFiles(mask):
    for f in glob.iglob(mask, recursive=True):
        if os.path.isfile(f):
            yield f


def searchFilesystem(args):
    tokenMap, tokenCombos = tokens.initTokensMap()

    if args.verbose:
        print("[+] scanning", args.mask)

    pool = Pool(int(args.max_threads))
    pool.map(partial(doSearchFilesystem, args, tokenMap, tokenCombos), findFiles(args.mask))
    pool.close()
    pool.join()


parser = argparse.ArgumentParser()
argcomplete.autocomplete(parser)
parser.add_argument('-t', '--threads', action='store', dest='max_threads', help='Max threads to speed the file handling', default="3")
parser.add_argument('-m', '--mask', action='store', dest='mask', help='Specify file mask (-m "*.java")')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output', default=False)
parser.add_argument('-s', '--slack', action='store_true', help='Enable slack notifications', default=False)
parser.add_argument('-tg', '--telegram', action='store_true', help='Enable telegram notifications', default=False)
parser.add_argument('-w', '--wordlist', action='store', dest='wordlist', help='Create a wordlist that fills dynamically with discovered filenames')
args = parser.parse_args()

if not args.mask or args.mask == "":
    print('No mask (-m or --mask) is specified, searching all files in the current directory')
    args.mask = './**/*'
    fileMask = args.mask

fileMask = args.mask
path_script = os.path.dirname(os.path.realpath(__file__))

# If wordlist, check if file is binary initialized for mmap
if args.wordlist:
    initFile(args.wordlist)

# Init URL file
initFile(config.GITHUB_URL_FILE)

# Search filesystem
responses = searchFilesystem(args)
