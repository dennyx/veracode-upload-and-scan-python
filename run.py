import argparse
import sys
import subprocess
import time
import logging


# args

parser = argparse.ArgumentParser()
parser.add_argument('api_wrapper_jar', help='file path to Veracode API Java wrapper')
parser.add_argument('id', help='Veracode API credentials ID')
parser.add_argument('key', help='Veracode API credentials key')
parser.add_argument('appname', help='Veracode application profile name')
parser.add_argument('version', help='Scan name')
group = parser.add_mutually_exclusive_group()
group.add_argument('--sandboxname', help='Veracode sandbox name')
group.add_argument('--break_the_build', action="store_true", help='Break the build if scan policy compliance fails')
parser.add_argument('--wait_interval', type=int, default=30, help='Time interval (s) between scan status checks, default = 30s')
parser.add_argument('--wait_max', type=int, default=3600, help='Maxiumum time (s) to wait for scan to complete, default = 1h')
args = parser.parse_args()


# helpers

def get_substring(s, leader, trailer):
    end_of_leader = s.index(leader) + len(leader)
    start_of_trailer = s.index(trailer, end_of_leader)
    return s[end_of_leader:start_of_trailer]


# setup

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='[%y.%m.%d %H:%M:%S]', level=logging.INFO)

base_command = ['java', '-jar', args.api_wrapper_jar, '-vid', args.id, '-vkey', args.key]


# upload veracode.zip, possibly to a sandbox

command = base_command + ['-action', 'UploadAndScan', '-createprofile', 'false', '-appname', args.appname, '-version', args.version, '-filepath', 'veracode.zip']
if args.sandboxname:
    command = command + ['-sandboxname', args.sandboxname]
upload = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
stdout = upload.communicate()[0]
print(stdout)

if 'The build_id of the new build is' in stdout:
    try:
        app_id = get_substring(stdout, 'appid=', ')')
        build_id = get_substring(stdout, 'The build_id of the new build is "', '"')
        if args.sandboxname:
            sandbox_id = get_substring(stdout, 'sandboxid=', ')')
    except ValueError as e:
        print(e)
        sys.exit(1)

    # watch scan status

    if args.break_the_build:
        command = base_command + ['-action', 'GetBuildInfo', '-appid', app_id, '-buildid', build_id]

        wait_so_far = 0
        while True:
            build_info = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout = build_info.communicate()[0]
            logging.info('<build ' + get_substring(stdout, '<build ', '>') + '>')

            if 'results_ready="true"' in stdout:
                if args.sandboxname:
                    logging.info('Scan complete in sandbox ' + args.sandboxname)
                    sys.exit(0)

                if all('policy_compliance_status="' + x not in stdout for x in ['Calculating...', 'Not Assessed']):
                    policy_compliance_status = get_substring(stdout, 'policy_compliance_status="', '"')
                    logging.info('Scan complete, policy compliance status: ' + policy_compliance_status)
                    if policy_compliance_status in ['Conditional Pass', 'Pass']:
                        sys.exit(0)
                    else:
                        sys.exit(1)

            if wait_so_far >= args.wait_max:
                logging.info('Scan did not complete within timeout')
                sys.exit(1)
            wait_so_far += args.wait_interval
            time.sleep(args.wait_interval)

else:
    sys.exit(2)
