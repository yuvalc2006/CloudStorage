# CloudStorage

CloudStorage is a cloud server application designed for secure and encrypted file storage of any size. The project consists of server-side code implemented in Python and client-side code written in C++. It uses a custom network protocol to ensure efficient and secure communication between the client and server.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributors](#contributors)

## Installation

To install CloudStorage, clone the repository and install the required dependencies:

```bash
git clone https://github.com/yuvalc2006/CloudStorage.git
cd CloudStorage
pip install -r requirements.txt
```

## Usage

1. **Run the server**: Execute the main.py script to start up the server.
2. **Set up client information**: in the client's folder, add a "transfer.info" file in this format:
  server ip:server port
  name
  path to file you want uploaded
3. **Run the Client**: Now, you can run the client and the file will upload to the server.

## Examples

For a visual demonstration, watch the running example on [YouTube](https://www.youtube.com/watch?v=3sQVSLuqACo). 

## Contributors

- [Yuval Cohen](https://github.com/yuvalc2006)
