import os
import argparse
import mmap
import winreg

parser = argparse.ArgumentParser(
    description='WinEnum.py - Runs permission checks against services, tasks, files, and registry.')
parser.add_argument(
    '--exepath', type=str, help='Path to the accesschk executable.', required=True)
opts = parser.parse_args()

if not os.path.isfile(opts.exepath):
    print('{0} does not appear to be a valid file.'.format(opts.exepath))
    print(parser.format_help())
    exit(1)


def find(s, ch):
    """ Finds all locations of a specified character in a string. """
    return [i for i, ltr in enumerate(s) if ltr == ch]


def parse_file_path(full_path):
    """ Parses the beginning file path discarding any additional parameters or switches.  Used to acquire the first
    directory and file path in a provided string. """
    quotes = find(full_path, '"')
    if len(quotes) >= 2 and quotes[0] == 0:
        file_path = '{0}"'.format(full_path[:quotes[1]])
        path_slashes = find(file_path, '\\')
        directory_path = '{0}"'.format(file_path[:path_slashes[len(path_slashes) - 1]])
    else:
        path_space = find(full_path, ' ')
        if len(path_space) > 0:
            file_path = full_path[:path_space[0]]
            path_slashes = find(file_path, '\\')
            directory_path = '"{0}"'.format(file_path[:path_slashes[len(path_slashes) - 1]])
        else:
            path_slashes = find(full_path, '\\')
            directory_path = '"{0}"'.format(full_path[:path_slashes[len(path_slashes) - 1]])
            file_path = '"{0}"'.format(full_path)

    return file_path, directory_path


def get_service_list():
    """ Gets a list of all Windows services. """
    services = []
    for line in os.popen('sc query').read().splitlines():
        if line.startswith('SERVICE_NAME'):
            pair = line.split(':')
            services.append(pair[1].strip())

    return services


def get_service_binary_path(service_name):
    """ Gets the binary path for a given Windows service name. """
    for line in os.popen('sc qc "{0}"'.format(service_name)).read().splitlines():
        values = line.split(' : ')

        if len(values) > 1:
            if values[0].strip() == 'BINARY_PATH_NAME':
                return values[1]
    return ''


def find_file_names(names, path):
    """ Finds files the have a name containing any of the text in the provided string list 'names'. """
    for root, dirs, files in os.walk(path):
        for file in files:
            for name in names:
                if name in file:
                    print(os.path.join(root, file))


def find_text_in_file(text, extensions, path):
    """ Finds files that contain the provided text. """
    for root, dirs, files in os.walk(path):
        for file in files:
            fullpath = os.path.join(root, file)
            filename, file_extension = os.path.splitext(fullpath)
            if file_extension.lower() in extensions:
                try:
                    with open(fullpath, 'rb', 0) as current_file, \
                            mmap.mmap(current_file.fileno(), 0, access=mmap.ACCESS_READ) as s:
                        if s.find(text) != -1:
                            print(fullpath)
                except Exception:
                    pass


def walk_registry(hkey, path, access_flags, keywords, onerror=None):
    """ Walks all keys of the registry searching for values that match any of the provided 'keywords'. """
    try:
        key = winreg.OpenKey(hkey, path, access_flags)
    except OSError as e:
        if onerror is not None:
            onerror(e)
        return

    i = 0
    sub_keys = []
    with key:
        while True:
            try:
                sub_keys.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1

        i = 0
        while True:
            try:
                data = winreg.EnumValue(key, i)
                i += 1
                for keyword in keywords:
                    if keyword.lower() in str(data[0]).lower():
                        if hkey == winreg.HKEY_LOCAL_MACHINE:
                            hive = 'HKLM\\'
                        else:
                            hive = 'HKCU\\'

                        print('{0}\\{1}\\{2} = {3}'.format(hive, path, data[0], data[1]))
            except OSError:
                break

        for key in sub_keys:
            next_path = os.path.join(path, key)
            for item in walk_registry(hkey, next_path, access_flags, keywords, onerror):
                yield item


print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
print('                        WINDOWS ENUMERATION SCRIPT')
print('                   (@ciph34block | tdmathison.github.io)')
print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

print()
print('===============================================================================')
print('[*] Performing systeminfo check')
print('===============================================================================')
print()
for line in os.popen('systeminfo').read().splitlines():
    print(line)

print()
print('===============================================================================')
print('[*] Performing quick Windows service checks for write access')
print('===============================================================================')
print()
groups = ['Authenticated Users', 'Users', 'Everyone']

for group in groups:
    print('Checking "{0}"'.format(group))
    for line in os.popen('"{0}" -uwcqv "{1}" * -nobanner /accepteula'.format(opts.exepath, group)).read().splitlines():
        print(line)

print('===============================================================================')
print('[*] Performing full Windows service dump')
print('===============================================================================')

# get list of services
services = get_service_list()

# get details on each service
for service in services:
    print('SERVICE_NAME: {0}'.format(service))
    binary_path = get_service_binary_path(service)

    print()
    print('Service permissions')
    print('-------------------')
    for line in os.popen(
            '"{0}" -ucqv "{1}" -nobanner /accepteula'.format(opts.exepath, service)).read().splitlines():
        print(line)

    print()
    print('File permissions')
    print('----------------')
    file_path, directory_path = parse_file_path(binary_path)

    for line in os.popen('icacls {0}'.format(file_path)).read().splitlines():
        if not line.startswith('Successfully') and not line.strip() == '':
            print(line)

    print()
    print('Directory permissions')
    print('---------------------')
    for line in os.popen('icacls {0}'.format(directory_path)).read().splitlines():
        if not line.startswith('Successfully') and not line.strip() == '':
            print(line)

    print('-------------------------------------------------------------------------------')

tasks = []
task = ['', '', '']

print()
print('===============================================================================')
print('[*] Performing scheduled tasks dump')
print('===============================================================================')

for line in os.popen('schtasks /query /v /fo list').read().splitlines():
    if line.strip() == '':
        continue

    pairs = line.split(':')

    if len(pairs) == 2:
        key = pairs[0].strip()
        value = ''.join([x.strip() for index, x in enumerate(pairs) if index > 0])

        if key == 'TaskName':
            task[0] = value
        elif key == 'Task To Run':
            quotes = find(value, '"')
            binary_path = ''
            if len(quotes) >= 2 and quotes[0] == 0:  # multiple quotes found and the starting path is quoted
                value = '{0}"'.format(value[:quotes[1]])
            else:
                space = find(value, ' ')
                if len(space) > 0:
                    value = value[:space[0]]
                else:
                    value = '"{0}"'.format(value)

            if os.path.isfile(os.path.expandvars(value)):
                task[1] = value
        elif key == 'Run As User':
            task[2] = value

            if task[1] != '':
                tasks.append(task)
                task = ['', '', '']

for item in tasks:
    print('TaskName   : {0}'.format(item[0]))
    print('Task To Run: {0}'.format(item[1]))
    print('Run As User: {0}'.format(item[2]))
    print()

    print('File permissions')
    print('----------------')
    for line in os.popen('icacls {0}'.format(os.path.expandvars(item[1]))).read().splitlines():
        if not line.startswith('Successfully') and not line.strip() == '':
            print(line)

    print()
    print('Directory permissions')
    print('---------------------')
    file_path, directory_path = parse_file_path(item[1])
    for line in os.popen('icacls {0}'.format(os.path.expandvars(directory_path))).read().splitlines():
        if not line.startswith('Successfully') and not line.strip() == '':
            print(line)

    print('-------------------------------------------------------------------------------')

print()
print('===============================================================================')
print('[*] Performing filename search (files of potential interest based on name)')
print('===============================================================================')
find_file_names(['unattend.xml', 'sysprep.inf', 'sysprep.xml'], os.path.splitdrive(os.getcwd())[0] + '\\')
find_file_names(['.config', 'pass', 'cred', 'vnc', '.pub', '.pkr', '.skr', '.pgp', '.pem'],
                os.path.splitdrive(os.getcwd())[0] + '\\')

print()
print('===============================================================================')
print('[*] Performing search for "password" in content of files')
print('===============================================================================')
find_text_in_file(b'password', ['.xml', '.ini', '.txt'], os.path.splitdrive(os.getcwd())[0] + '\\')

print()
print('===============================================================================')
print('[*] Performing search for "credentials" in content of files')
print('===============================================================================')
find_text_in_file(b'credentials', ['.xml', '.ini', '.txt'], os.path.splitdrive(os.getcwd())[0] + '\\')

print()
print('===============================================================================')
print('[*] Performing search in registry')
print('===============================================================================')
access_flags = [0]

if hasattr(winreg, "KEY_WOW64_32KEY"):
    access_flags.append(winreg.KEY_WOW64_64KEY)
else:
    access_flags.append(winreg.KEY_WOW64_32KEY)

for flag in access_flags:
    search = list(walk_registry(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE',
                                winreg.KEY_READ | flag,
                                ['password', 'credentials', 'creds', 'AlwaysInstallElevated', 'AutoAdminLogon',
                                 'DefaultUserName', 'DefaultPassword', 'DefaultDomainName']))
    search = list(walk_registry(winreg.HKEY_CURRENT_USER, 'SOFTWARE',
                                winreg.KEY_READ | flag,
                                ['password', 'credentials', 'creds', 'AlwaysInstallElevated', 'AutoAdminLogon',
                                 'DefaultUserName', 'DefaultPassword', 'DefaultDomainName']))
