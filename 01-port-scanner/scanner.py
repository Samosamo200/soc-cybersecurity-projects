import socket
import argparse
import concurrent.futures

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        s.close()
        return port if result == 0 else None
    except:
        return None

def scan(host, start, end):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in range(start, end + 1)}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('--ports', default='1-1024')
    args = parser.parse_args()
    start, end = map(int, args.ports.split('-'))
    print(f'Skanner {args.host} ({start}-{end})...')
    ports = scan(args.host, start, end)
    if ports:
        for p in ports:
            print(f'  {p}/tcp  open')
    else:
        print('  Ingen aapne porter funnet')

if __name__ == '__main__':
    main()
