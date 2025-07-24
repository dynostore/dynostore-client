# dynostore/client/cli.py

import argparse
from dynostore.client import Client


def main():
    parser = argparse.ArgumentParser(description='DynoStore CLI Client')
    parser.add_argument('--server', required=True,
                        help='Metadata server address (e.g., 127.0.0.1:5000)')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # PUT
    put_parser = subparsers.add_parser('put', help='Upload data to DynoStore')
    put_parser.add_argument('file', help='Path to the file to upload')
    put_parser.add_argument('--catalog', required=True, help='Catalog name')
    put_parser.add_argument(
        '--key', help='Key to use (default: generated UUID)')
    put_parser.add_argument(
        '--encrypt', action='store_true', help='Encrypt the data')
    put_parser.add_argument('--resiliency', type=int,
                            default=1, help='Resiliency level')

    # GET
    get_parser = subparsers.add_parser(
        'get', help='Download data from DynoStore')
    get_parser.add_argument('key', help='Key of the object to download')
    get_parser.add_argument(
        '--output', help='Output file to write to (default: stdout)')

    # EXISTS
    exists_parser = subparsers.add_parser(
        'exists', help='Check if object exists')
    exists_parser.add_argument('key', help='Key to check')

    # EVICT
    evict_parser = subparsers.add_parser(
        'evict', help='Remove object from store')
    evict_parser.add_argument('key', help='Key to delete')

    args = parser.parse_args()
    client = Client(metadata_server=args.server)

    if args.command == 'put':
        with open(args.file, 'rb') as f:
            data = f.read()
        result = client.put(
            data=data, 
            catalog=args.catalog, 
            is_encrypted=args.encrypt, 
            resiliency=args.resiliency
        )
        print("Upload successful:", result)

    elif args.command == 'get':
        data = client.get(args.key)
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(data)
        else:
            print(data.decode(errors='replace'))

    elif args.command == 'exists':
        exists = client.exists(args.key)
        print(f"Exists: {exists}")

    elif args.command == 'evict':
        client.evict(args.key)
        print("Object evicted successfully.")
