import argparse
import asyncio
import os
import sys
import logging
from pathlib import Path
from dynostore.client import Client
from dynostore.auth.authenticate import DeviceAuthenticator
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

class ISO8601UTCFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds")  # 2025-09-10T14:47:10.114+00:00

LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()


LOG_DIR = os.getenv("LOG_DIR", "./logs")
LOG_FILE = os.path.join(LOG_DIR, os.getenv("LOG_FILE", "dynostore.log"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG").upper()
CONSOLE_LEVEL = os.getenv("LOG_CONSOLE_LEVEL", "INFO").upper()
FILE_LEVEL = os.getenv("LOG_FILE_LEVEL", LOG_LEVEL)

level_int = getattr(logging, LOG_LEVEL, logging.DEBUG)

os.makedirs(LOG_DIR, exist_ok=True)

fmt_str = "%(asctime)s,%(levelname)s,%(name)s,%(message)s"

# root = logging.getLogger()
# root.setLevel(level_int)
# root.handlers.clear()  # optional: avoid duplicate handlers on reload

# attach handlers to the dynostore package logger only
pkg_logger = logging.getLogger("dynostore")
pkg_logger.setLevel(level_int)
pkg_logger.propagate = False  


# Console
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(level_int)
ch.setFormatter(ISO8601UTCFormatter(fmt_str))
pkg_logger.addHandler(ch)

# Rotating file
fh = RotatingFileHandler(LOG_FILE, maxBytes=50*1024*1024, backupCount=10, encoding="utf-8")
fh.setLevel(level_int)
fh.setFormatter(ISO8601UTCFormatter(fmt_str))
pkg_logger.addHandler(fh)

logger = logging.getLogger(__name__)

def _log(operation: str, key: str, phase: str, status: str, msg: str = ""):
    # Format: SERVICE, OPERATION, OBJECTKEY, START/END, Status, MSG
    logger.debug(f"CLI,{operation},{key},{phase},{status},{msg}")


async def async_main():
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
    put_parser.add_argument('--recursive', action='store_true', help='Recursively upload directories')

    # GET
    get_parser = subparsers.add_parser('get', help='Download data from DynoStore')
    get_parser.add_argument('key', help='Key of the object to download')
    get_parser.add_argument('--output', help='Output file to write to (default: stdout)')

    # GET Catalog
    get_catalog_parser = subparsers.add_parser('get_catalog', help='Get all objects in a catalog')
    get_catalog_parser.add_argument('catalog', help='Catalog name to retrieve objects from')
    get_catalog_parser.add_argument('output', help='Output directory to write the catalog to')

    # LOGIN / LOGOUT
    login_parser = subparsers.add_parser('login', help='Authenticate and save a user token')
    login_parser.add_argument('--force', action='store_true', help='Force re-authentication even if a token exists')

    logout_parser = subparsers.add_parser('logout', help='Remove stored authentication token')

    # EXISTS
    exists_parser = subparsers.add_parser('exists', help='Check if object exists')
    exists_parser.add_argument('key', help='Key to check')

    # EVICT
    evict_parser = subparsers.add_parser('evict', help='Remove object from store')
    evict_parser.add_argument('key', help='Key to delete')

    args = parser.parse_args()

    # Default logging setup (caller can override)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s,%(levelname)s,%(name)s,%(message)s",
    )

    try:
        if args.command == 'login':
            authenticator = DeviceAuthenticator(auth_url=args.server)
            authenticator.authenticate(force=args.force)
            return 0

        if args.command == 'logout':
            authenticator = DeviceAuthenticator(auth_url=args.server)
            authenticator.logout()
            return 0

        client = Client(metadata_server=args.server)

        if args.command == 'put':
            
            if args.recursive:
                if not os.path.isdir(args.file):
                    return 1

                dir_path = Path(args.file)
                
                tasks = []
                for filepath in dir_path.rglob('*'):
                    if filepath.is_file():
                        rel_path = filepath.relative_to(dir_path)
                        if rel_path.parent == Path('.'):
                            catalog_name = args.catalog
                        else:
                            catalog_name = f"{args.catalog}_{rel_path.parent.as_posix().replace('/', '_')}"
                            
                        with open(filepath, 'rb') as f:
                            data = f.read()

                        print(f"Uploading {filepath} to catalog {catalog_name} with key {args.key or 'generated'}")
                        tasks.append(client.put(
                            data=data,
                            catalog=catalog_name,
                            is_encrypted=args.encrypt,
                            resiliency=args.resiliency,
                            name=filepath.name,
                            key=args.key  # may be None -> generated by Client
                        ))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        print(f"Error in upload: {r}", file=sys.stderr)
                obj_key = "recursive_batch"
            else:
                with open(args.file, 'rb') as f:
                    data = f.read()
                result = await client.put(
                    data=data,
                    catalog=args.catalog,
                    is_encrypted=args.encrypt,
                    resiliency=args.resiliency,
                    key=args.key
                )
                obj_key = (result or {}).get("key_object", args.key or "-")

        elif args.command == 'get':
            data = await client.get(args.key)
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(data)
            else:
                # no prints by request; log a small preview
                preview = repr(data[:80])

        elif args.command == 'get_catalog':
            paths = await client.get_files_in_catalog(args.catalog, output_dir=args.output)

        elif args.command == 'exists':
            exists = await client.exists(args.key)

        elif args.command == 'evict':
            await client.evict(args.key)

    except Exception as e:
        print(f"Error executing command '{args.command}': {e}", file=sys.stderr)
        _log(args.command.upper(), getattr(args, "key", "-") or "-", "END", "ERROR", f"msg={e}")
        return 1

    return 0


def main():
    return asyncio.run(async_main())

if __name__ == '__main__':
    sys.exit(main())
