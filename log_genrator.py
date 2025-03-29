import random
from datetime import datetime, timedelta

ips = ['192.168.1.{}'.format(i) for i in range(1, 50)]
paths = ['/','/about','/contact','/login','/wp-admin','/admin','/config']

def generate_log_entry():
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 86400))
    ip = random.choice(ips)
    path = random.choice(paths)
    status = random.choices(
        ['200','404','500','403','302'],
        weights=[80, 10, 5, 3, 2]
    )[0]
    
    return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {path} HTTP/1.1" {status} 5432\n'

# Generate sample log file
with open('sample_logs/access.log', 'w') as f:
    for _ in range(10000):
        f.write(generate_log_entry())