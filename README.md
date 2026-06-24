# DynoStore Client

A command-line client for interacting with the DynoStore metadata server. 

## Installation

The client requires Python 3.9 or higher. You can install it locally using `pip`:

```bash
pip install .
```

This will make the `dynostore` command available in your terminal.

## Global Options

All commands require the `--server` argument to specify the metadata server address.

- `--server <address>`: Metadata server address (e.g., `127.0.0.1:5000`)

## Usage

### Authentication

#### Login
Authenticate and save a user token.

```bash
dynostore --server <server_address> login [--force]
```
- `--force`: Force re-authentication even if a token already exists.

#### Logout
Remove the stored authentication token.

```bash
dynostore --server <server_address> logout
```

### Data Operations

#### Upload Data (`put`)
Upload a file or directory to DynoStore.

```bash
dynostore --server <server_address> put <file_path> --catalog <catalog_name> [options]
```
- `<file_path>`: Path to the file or directory to upload.
- `--catalog <catalog_name>`: (Required) Catalog name to store the data under.
- `--key <key>`: Key to use (default: generated UUID).
- `--encrypt`: Encrypt the data before uploading.
- `--resiliency <level>`: Resiliency level (default: `1`).
- `--recursive`: Recursively upload directories. If specified, `<file_path>` should be a directory.

#### Download Data (`get`)
Download an object from DynoStore.

```bash
dynostore --server <server_address> get <key> [--output <file_path>]
```
- `<key>`: Key of the object to download.
- `--output <file_path>`: Output file to write to. If omitted, the data will be written to `stdout`.

#### Download Catalog (`get_catalog`)
Download all objects within a specific catalog.

```bash
dynostore --server <server_address> get_catalog <catalog_name> <output_directory>
```
- `<catalog_name>`: Catalog name to retrieve objects from.
- `<output_directory>`: Output directory to write the catalog files to.

### Object Management

#### Check Existence (`exists`)
Check if an object exists in the store.

```bash
dynostore --server <server_address> exists <key>
```
- `<key>`: Key of the object to check.

#### Evict Object (`evict`)
Remove an object from the store.

```bash
dynostore --server <server_address> evict <key>
```
- `<key>`: Key of the object to delete.

## Logging

Logging can be configured via environment variables:
- `LOG_DIR`: Directory to store log files (default: `./logs`).
- `LOG_FILE`: Name of the log file (default: `dynostore.log`).
- `LOG_LEVEL`: Logging level (default: `DEBUG`).
- `LOG_CONSOLE_LEVEL`: Logging level for standard output (default: `INFO`).
- `LOG_FILE_LEVEL`: Logging level for the file (defaults to `LOG_LEVEL`).

## Development

To run the unit tests, you will need to install the optional testing dependencies. We recommend using a virtual environment.

```bash
# Install the client along with the test dependencies
pip install ".[test]"

# Run the test suite using pytest
pytest tests/
```
