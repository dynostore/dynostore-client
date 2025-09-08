# dynostore/client/cli.py

import argparse
import os
import sys
import logging
from pathlib import Path
from dynostore.client import Client


logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description='DynoStore CLI Client')
    parser.add_argument('--server', required=True,
                        help='Metadata server address (e.g., 127.0.0.1:5000)')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # PUT
    put_parser = subparsers.add_parser('put', help='Upload data to DynoStore')
    put_parser.add_argument('file', help='Path to the file to upload')
    put_parser.add_argument('--catalog', required=True, help='Catalog name')
    put_parser.add_argument('--key', help='Key to use (default: generated UUID)')
    put_parser.add_argument('--encrypt', action='store_true', help='Encrypt the data')
    put_parser.add_argument('--resiliency', type=int, default=1, help='Resiliency level')
    put_parser.add_argument('--recursive', action='store_true',
                            help='Recursively upload directories')

    # GET
    get_parser = subparsers.add_parser('get', help='Download data from DynoStore')
    get_parser.add_argument('key', help='Key of the object to download')
    get_parser.add_argument('--output', help='Output file to write to (default: stdout)')

    # GET Catalog
    get_catalog_parser = subparsers.add_parser('get_catalog', help='Get all objects in a catalog')
    get_catalog_parser.add_argument('catalog', help='Catalog name to retrieve objects from')
    get_catalog_parser.add_argument('output', help='Output directory to write the catalog to')

    # EXISTS
    exists_parser = subparsers.add_parser('exists', help='Check if object exists')
    exists_parser.add_argument('key', help='Key to check')

    # EVICT
    evict_parser = subparsers.add_parser('evict', help='Remove object from store')
    evict_parser.add_argument('key', help='Key to delete')

    args = parser.parse_args()

    # Basic logging setup
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s,%(levelname)s,%(name)s,%(message)s",
    )

    client = Client(metadata_server=args.server)

    try:
        if args.command == 'put':
            logger.debug("CLI,PUT,START,file=%s,catalog=%s,recursive=%s",
                         args.file, args.catalog, args.recursive)

            if args.recursive:
                if not os.path.isdir(args.file):
                    logger.error("CLI,PUT,ERROR,not_a_directory,path=%s", args.file)
                    return 1

                dir_path = Path(args.file)
                file_paths = [str(f) for f in dir_path.iterdir() if f.is_file()]

                for filepath in file_paths:
                    logger.debug("CLI,PUT,FILE,START,path=%s", filepath)
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    result = client.put(
                        data=data,
                        catalog=args.catalog,
                        is_encrypted=args.encrypt,
                        resiliency=args.resiliency,
                        name=os.path.basename(filepath)
                    )
                    logger.debug("CLI,PUT,FILE,END,path=%s,result=%s", filepath, result)
            else:
                with open(args.file, 'rb') as f:
                    data = f.read()
                result = client.put(
                    data=data,
                    catalog=args.catalog,
                    is_encrypted=args.encrypt,
                    resiliency=args.resiliency
                )
                logger.debug("CLI,PUT,SINGLE,END,file=%s,result=%s", args.file, result)

        elif args.command == 'get':
            logger.debug("CLI,GET,START,key=%s", args.key)
            data = client.get(args.key)
            if data is not None:
                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(data)
                    logger.debug("CLI,GET,END,SUCCESS,key=%s,output=%s,bytes=%d",
                                 args.key, args.output, len(data))
                else:
                    logger.info("CLI,GET,END,SUCCESS,key=%s,stdout_preview=%s,bytes=%d",
                                args.key, data[:80], len(data))
            else:
                logger.error("CLI,GET,END,FAILED,key=%s", args.key)

        elif args.command == 'get_catalog':
            logger.debug("CLI,GET_CATALOG,START,catalog=%s,output_dir=%s",
                         args.catalog, args.output)
            result = client.get_files_in_catalog(args.catalog, output_dir=args.output)
            logger.debug("CLI,GET_CATALOG,END,catalog=%s,written_count=%d",
                         args.catalog, len(result))

        elif args.command == 'exists':
            logger.debug("CLI,EXISTS,START,key=%s", args.key)
            exists = client.exists(args.key)
            logger.debug("CLI,EXISTS,END,key=%s,exists=%s", args.key, exists)

        elif args.command == 'evict':
            logger.debug("CLI,EVICT,START,key=%s", args.key)
            client.evict(args.key)
            logger.debug("CLI,EVICT,END,SUCCESS,key=%s", args.key)

    except Exception as e:
        logger.exception("CLI,%s,ERROR,%s", args.command.upper(), e)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
