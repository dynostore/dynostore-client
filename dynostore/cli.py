# dynostore/client/cli.py

import argparse
import os
from dynostore.client import Client
from pathlib import Path



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
    put_parser.add_argument('--recursive', action='store_true',
                            help='Recursively upload directories')    

    # GET
    get_parser = subparsers.add_parser(
        'get', help='Download data from DynoStore')
    get_parser.add_argument('key', help='Key of the object to download')
    get_parser.add_argument(
        '--output', help='Output file to write to (default: stdout)')
    
    # GET Catalog
    get_parser = subparsers.add_parser(
        'get_catalog', help='Get all objects in a catalog')
    get_parser.add_argument('catalog', help='Catalog name to retrieve objects from')
    get_parser.add_argument(
        'output', help='Output directory to write the catalog to (default: stdout)')

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
        if args.recursive:
            # Check if path is a directory
            if not os.path.isdir(args.file):
                print(f"Error: {args.file} is not a directory.")
                return 1
            # Just upload all files in the directory
            dir_path = Path(args.file)
            file_paths = [str(f) for f in dir_path.iterdir() if f.is_file()]

            
            for filepath in file_paths:
                print(f"Uploading {filepath}...")
                with open(filepath, 'rb') as f:
                    data = f.read()
                result = client.put(
                    data=data, 
                    catalog=args.catalog, 
                    is_encrypted=args.encrypt, 
                    resiliency=args.resiliency,
                    name=os.path.basename(filepath)
                )
                print(f"Uploaded {filepath}: {result}")
        else:
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
        if data is not None:
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(data)
            else:
                print(data.decode(errors='replace'))

    elif args.command == 'get_catalog':
        print("Retrieving objects from catalog:", args.catalog)
        print(args)
        result = client.get_files_in_catalog(args.catalog, output_dir=args.output)

    elif args.command == 'exists':
        exists = client.exists(args.key)
        print(f"Exists: {exists}")

    elif args.command == 'evict':
        client.evict(args.key)
        print("Object evicted successfully.")


if __name__ == '__main__':
    main()