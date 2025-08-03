from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

def batch_scan(self, ip_list):
    with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
        results = {
            ip: res for ip, res in zip(
                ip_list,
                tqdm(executor.map(self.scan_target, ip_list), total=len(ip_list))
            )
        }
    return results
