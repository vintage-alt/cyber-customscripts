import asyncio
import sys
import httpx

async def check_url(client, url, semaphore):
    async with semaphore:
        try:
            response = await client.get(url, follow_redirects=False, timeout=5.0)
            if response.status_code not in [404, 403]:
                print(f"[+] Status {response.status_code}: {url} (Length: {len(response.content)})")
            elif response.status_code == 403:
                print(f"[?] Status 403 (Forbidden): {url}")
        except httpx.RequestError:
            pass

async def main(base_url, wordlist_file):
    try:
        with open(wordlist_file, "r") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {wordlist_file}")
        return

    semaphore = asyncio.Semaphore(20) # Concurrency limit
    async with httpx.Client() as client:
        tasks = []
        for path in paths:
            target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            tasks.append(check_url(client, target_url, semaphore))
        print(f"[*] Fuzzing {base_url} with {len(paths)} paths...")
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python endpoint_fuzzer.py <BASE_URL> <WORDLIST_PATH>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2]))