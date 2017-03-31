import sys
import paramiko


class SshClient(object):
    def __init__(self, ip, username, password, port=22):
        self._ip = ip
        self._username = username
        self._password = password
        self._port = port
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._connect()

    def _connect(self):
        self._client.connect(hostname=self._ip,
                             port=self._port,
                             username=self._username,
                             password=self._password)

    def execute(self, command):
        stdin, stdout, stderr = self._client.exec_command(command)
        return stdin, stdout, stderr


class FindLogs(object):
    def __init__(self, ip, port=22):
        self._username = None
        self._password = None
        self._auth_data(ip)
        self._log_names = None
        self._log_output = {}
        self._ssh = SshClient(ip, self.username, self.password, port=port)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, username):
        self._username = username

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = password

    def find_logs(self, log_pattern, root_dir=None, postfix=None):
        command = "find {0} -name '*{1}{2}' 2>/dev/null".format(
            root_dir if root_dir else '/', log_pattern,
            postfix if postfix is not None else '*')
        _, stdout, _ = self._ssh.execute(command)
        log_names = stdout.readlines()
        self._log_names = [log[:-1] for log in log_names]
        return self._log_names

    def grep_logs(self, matcher, rows_count=10, grep_only_first_log=True):
        log_names = []
        if grep_only_first_log:
            log_names.append(self._log_names[0])
        else:
            log_names = self._log_names
        for log in log_names:
            command = \
                "grep '{matcher}' {log_name} -A{count} -B{count}".format(
                    matcher=matcher, log_name=log, count=rows_count)
            _, stdout, _ = self._ssh.execute(command)
            self._log_output[log] = stdout.readlines()
        return self._log_output

    def print_logs(self):
        breaker = 100 * '#'
        print breaker
        for log in self._log_output:
            print log
            print len(log) * '-'
            for line in self._log_output[log]:
                print line
        print breaker

    def _auth_data(self, ip_addr='10.10.10.10'):
        self.username = 'admin'
        self.password = 'admin'


def main():
    args = sys.argv
    ip = args[1]
    mask = args[2]
    pattern = args[3]
    flogs = FindLogs(ip, port=2222)
    flogs.find_logs(mask, '/var/log/', '')
    flogs.grep_logs(pattern, rows_count=100, grep_only_first_log=False)
    flogs.print_logs()

if __name__ == '__main__':
    main()
