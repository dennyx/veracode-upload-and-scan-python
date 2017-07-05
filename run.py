# run.py id key app_profile scan_name sandbox

import sys
import subprocess
import datetime
import time


wait = 10
total_wait = 3600


def get_substring(s, leader, trailer):
    end_of_leader = s.index(leader) + len(leader)
    start_of_trailer = s.index(trailer, end_of_leader)
    return s[end_of_leader:start_of_trailer]


def log_now():
    return '['+datetime.datetime.now().strftime("%y.%m.%d %H:%M:%S")+'] '


if len(sys.argv) >= 5:
    id = sys.argv[1]
    key = sys.argv[2]
    app_profile = sys.argv[3]
    scan_name = sys.argv[4]
    if len(sys.argv) >= 6:
        sandbox = sys.argv[5]
    else:
        sandbox = None
else:
    pass

scan_name = scan_name + ' ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

# upload veracode.zip, possibly to a sandbox

base_command = ['java', '-jar', 'VeracodeJavaAPI.jar',
                '-vid', id, '-vkey', key]
command = base_command + ['-action', 'UploadAndScan',
                          '-createprofile', 'false',
                          '-appname', app_profile,
                          '-version', scan_name,
                          '-filepath', 'veracode.zip']
if sandbox is not None:
    command = command + ['-sandboxname', sandbox]

upload = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
stdout = upload.stdout.decode(sys.stdout.encoding)
print(stdout)

if 'The build_id of the new build is' in stdout:
    try:
        app_id = get_substring(stdout, 'appid=', ')')
        build_id = get_substring(stdout, 'The build_id of the new build is "', '"')
        if sandbox is not None:
            sandbox_id = get_substring(stdout, 'sandboxid=', ')')
    except ValueError as e:
        print(e)
        sys.exit(1)

    # watch scan status

    command = base_command + ['-action', 'GetBuildInfo',
                              '-appid', app_id,
                              '-buildid', build_id]
    if sandbox is not None:
        command = command + ['-sandboxid', sandbox_id]

    wait_so_far = 0
    while True:
        build_info = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout = build_info.stdout.decode(sys.stdout.encoding)
        print(log_now() + '<build ' + get_substring(stdout, '<build ', '>') + '>')

        if 'results_ready="true"' in stdout:
            if sandbox is not None:
                print(log_now() + 'Scan complete')
                sys.exit(0)

            if all('policy_compliance_status="' + x not in stdout for x in ['Calculating...', 'Not Assessed']):
                policy_compliance_status = get_substring(stdout, 'policy_compliance_status="', '"')
                print(log_now() + 'Scan complete, policy compliance status: ' + policy_compliance_status)
                if policy_compliance_status in ['Conditional Pass', 'Pass']:
                    sys.exit(0)
                else:
                    sys.exit(1)

        if wait_so_far >= total_wait:
            print(log_now() + 'Scan did not complete within timeout')
            sys.exit(1)
        wait_so_far += wait
        time.sleep(wait)
else:
    sys.exit(500)
