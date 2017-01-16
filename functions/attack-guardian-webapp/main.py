# coding:utf-8
from __future__ import print_function

import os

import re
import json
import urllib
import boto3

import gzip
import ast
from collections import Counter

print('Loading function')

## Environmental settings
environment = os.environ['ENVIRONMENT']
waf_ip_set_id = os.environ['WAF_IP_SET_ID']
notification_sns_topic = os.environ['NOTIFICATION_SNS_TOPIC']
black_list_threshold_count = int(os.environ['BLACK_LIST_THRESHOLD_COUNT'])
slack_incomming_hook_url = os.environ['SLACK_INCOMMING_HOOK_URL']
slack_notification_enabled = int(os.environ['SLACK_NOTIFICATION_ENABLED'])

## codes
s3 = boto3.client('s3')
sns = boto3.client('sns')
waf = boto3.client('waf')

## white list
ip_address_ignore_policy = re.compile('^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*')

def handle(event, context):
    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key'].encode('utf8'))
    print(u'----------------------start:{key_name}------------------------------'.format(key_name = key))
    try:
        # open file, unzip
        s3.download_file(bucket, key, '/tmp/file.gz')
        f = gzip.open('/tmp/file.gz', 'rb')
        content = f.read()
        f.close

        # create black list
        ip_address_list = to_ip_address_list(content.decode('utf-8'))
        black_list = to_ip_black_list(ip_address_list)
        print(u'black list：', black_list)

        if len(black_list):
            print(u'block threshold: {threshold} '.format(threshold = black_list_threshold_count))

            # create ip set for waf
            update_ip_set=map(to_ip_set_for_waf, black_list)

            # create sns settings
            sns_settings=to_sns_notification_settings(black_list)

            # waf setting (side-effect function)
            waf_block(update_ip_set)

            # notification (side-effect functions)
            sns_notification(sns_settings)
            if slack_notification_enabled:
                slack_notification(black_list)
            else:
                pass
        else:
            print(u'nothing to do.')
            pass
        print(u'----------------------finish:{key_name}------------------------------'.format(key_name = key))
        return black_list
    except Exception as e:
        print(e)
        raise e

# from: String log file -> to: IP Address List.
def to_ip_address_list(file_string):
    result_list=[]
    for r in file_string.split('\n'):
        try:
            ip=ast.literal_eval(r)['host']
            if ('-' in ip) or ip == '':
                pass
            else:
                result_list.append(ip)
        except Exception as e:
            print(u'ignore: ',r ,e)
    return result_list

# from: IP address list -> to: black list
def to_ip_black_list(ip_list):
    black_list=[]
    counter=Counter(ip_list)
    print(u'aggregated:')
    for ip, cnt in counter.most_common():
        print(ip, cnt)
        if cnt > black_list_threshold_count and not ip_address_ignore_policy.search(ip):
            black_list.append(ip)
        else:
            pass
    return black_list

# from: IP address list -> to: WAF update request body.
def to_ip_set_for_waf(ip):
    ip_set = {'Action': 'INSERT'}
    descripter={'Type': 'IPV4'}
    descripter['Value']= str(ip) + '/32'
    ip_set['IPSetDescriptor']=descripter
    return ip_set

# from: IP address list -> sns settings dictionary.
def to_sns_notification_settings(ip_address_list):
    sns_settings={}
    sns_settings['subject']=str(environment)+' : AWS WAF Guardian blocked IPs'

    sns_body = {}
    sns_body["default"] = 'Block IP address list:\n'
    sns_body["default"] += '\n'.join(ip_address_list)

    sns_settings['body'] = sns_body
    return sns_settings

def waf_block(update_ip_set):
    token = waf.get_change_token()
    waf.update_ip_set(
        IPSetId=waf_ip_set_id,
        ChangeToken=token['ChangeToken'],
        Updates=update_ip_set
    )
    print(u'WAF:', waf.get_ip_set(IPSetId=waf_ip_set_id))
    return

def sns_notification(sns_settings):
    topic = notification_sns_topic
    region = 'ap-northeast-1'
    subject = sns_settings['subject']
    sns_body = sns_settings['body']
    sns.publish(
        TopicArn = topic,
        Message = json.dumps(sns_body, ensure_ascii=False),
        Subject = subject,
        MessageStructure = 'json'
    )
    return

def slack_notification(blocked_ips):
    url = slack_incomming_hook_url
    ips = ', '.join(blocked_ips)
    body = "ENV-{env}, Blocked IPs: {ips}".format(env = environment, ips = ips)
    params = urllib.urlencode({"payload": {"text": body}})
    f = urllib.urlopen(url, params)
    print(f.read())
    return
