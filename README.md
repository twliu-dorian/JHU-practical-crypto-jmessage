# JMessage Overview

This repository contains code and specifications for the JMessage system.

See the following resources:

- [JMessage Specification](specification.md)
- [How to run the JMessage server locally](running_server.md)

In addition, you will find code for the server and a skeleton of the unfinished Golang client.

## Using JMessage Program

JMessage is a simple messaging system built with Python for the server side and Go for the client side. This guide walks you through setting up and running the JMessage server and client.

### Prerequisites

Ensure you have Python 3 and Go installed on your system. You can verify the installations with the following commands:

```bash=
$ python3 --version
$ go version
```

### Setup

1. Install Required Python Packages
   First, install the necessary Python packages for the server. Navigate to the server directory and run:

```bash=
$ pip3 install -r requirements.txt # Recommended to use the requirements doc
```

If you're using a very old version of Python and encounter issues, try installing the packages individually:

```bash=
$ pip3 install flask sqlite3 passlib datetime
```

2. Run the Server

Start the JMessage server with the following command:

```bash=
$ python3 jmessage_server.py
```

3.Install Go and Build the Client Code
Ensure Go is installed, then compile the JMessage client using the provided Go source file:

```bash=
$ go build -o jmessage_client jmessage_client_unfinished.go
```

### Usage

#### Registering Users

To use JMessage, start by registering users. Here's how to register two example users, dorian and liu:

```bash=
$ ./jmessage_client -domain localhost -port 8080 -reg -username dorian -password 1234
$ ./jmessage_client -domain localhost -port 8080 -reg -username liu -password 1234
```

#### Start Messaging

If a user is already registered, you can log in without the -reg flag:
. Ensure both clients are running and logged in to exchange messages.

```bash=
# For user dorian
$ ./jmessage_client -domain localhost -port 8080 -username dorian -password 1234
# For user liu
$ ./jmessage_client -domain localhost -port 8080 -username liu -password 1234
```

Follow the on-screen prompts to send messages between clients.
