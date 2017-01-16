import unittest
import os

os.environ['ENVIRONMENT'] = 'local'
os.environ['WAF_IP_SET_ID'] = 'waf_id'
os.environ['NOTIFICATION_SNS_TOPIC'] = 'sns_topic'
os.environ['BLACK_LIST_THRESHOLD_COUNT'] = '1'
os.environ['SLACK_INCOMMING_HOOK_URL'] = 'slack_url'
os.environ['SLACK_NOTIFICATION_ENABLED'] = '1'
os.environ['AWS_DEFAULT_REGION'] = 'ap-northeast-1'

import main

class TestMain(unittest.TestCase):

    def test_to_ip_address_list(self):
        f = open('./example_access_log_file','r')
        file_string = f.read()
        f.close()
        expected = [
            '11.111.77.152',
            '11.111.77.152',
            '11.111.77.152'
        ]
        actual = main.to_ip_address_list(file_string)
        self.assertEqual(actual,expected)


    def test_to_ip_black_list(self):
        ip_list = [
            '10.255.255.255',
            '10.255.255.255',
            '127.0.0.1',
            '127.0.0.1',
            '172.22.22.122',
            '172.22.22.122',
            '192.168.22.122',
            '192.168.22.122',
            '53.244.122.210',
            '53.244.122.210'
        ]
        expected = ['53.244.122.210']
        actual = main.to_ip_black_list(ip_list)
        self.assertEqual(actual, expected)

    def test_to_ip_set_for_waf(self):
        ip = '53.246.127.33'
        expected = {'Action': 'INSERT', 'IPSetDescriptor': {'Type': 'IPV4', 'Value': ip + '/32'}}
        actual = main.to_ip_set_for_waf(ip)
        self.assertEqual(actual, expected)

    def test_to_sns_notification_settings(self):
        black_ip_list = [
            '53.244.122.210',
            '53.223.122.210',
            '53.112.122.210'
        ]
        expected = {'subject':'local : AWS WAF Guardian blocked IPs', 'body': {'default':'Block IP address list:\n53.244.122.210\n53.223.122.210\n53.112.122.210'}}
        actual = main.to_sns_notification_settings(black_ip_list)
        self.assertEqual(actual, expected)



if __name__ == '__main__':
    unittest.main()
