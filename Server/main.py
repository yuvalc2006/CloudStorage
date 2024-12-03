import server
import os
import warnings


# Function to check if the port number is valid
def is_valid_port(port):
    return 1 <= port <= 65535  # Valid port range


def get_port_number(file_name):
    try:
        # Check if the file exists
        if not os.path.exists(file_name):
            warnings.warn(f"The file '{file_name}' does not exist.", UserWarning)
            return default_port_number

        # Read the port number from the file
        with open(file_name, 'r') as file:
            lines = file.readlines()

            # Check if there's exactly one line
            if len(lines) != 1:
                warnings.warn("The file must contain exactly one line.", UserWarning)
                return default_port_number

            port_number_str = lines[0].strip()  # Read the first line and strip whitespace

            # Check if the line is a valid integer
            if not port_number_str.isdigit():
                warnings.warn("The line must contain a valid integer.", UserWarning)
                return default_port_number

            port_number = int(port_number_str)

            # Validate the port number
            if not is_valid_port(port_number):
                warnings.warn("The port number must be between 1 and 65535.", UserWarning)
                return default_port_number

        print(f"Port number read from file: {port_number}")

        return port_number

    except Exception as e:
        print(f"Error: {e}")


def stopServer(err):
    print(f"\nFatal Error: {err}\nMessageU Server will halt!")
    exit(1)


default_port_number = 1256

if __name__ == "__main__":
    file_name = "port.info"
    port = get_port_number(file_name)
    if port is None:
        stopServer(f"Failed to parse integer port from '{file_name}'!")
    svr = server.Server('', port)  # don't care about host.
    if not svr.start():
        stopServer(f"Server start exception: {svr.lastErr}")
