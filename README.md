# Alert Tracker

## Overview

Alert Tracker is a demonstration project showing how to obtain alert recipients from the Zabbix API for triggers associated with a selected host using the [zabbix_utils](https://github.com/zabbix/python-zabbix-utils) library. This project is a part of the [article](https://blog.zabbix.com/python-zabbix-utils-alert-tracker-tool/29010/) on Zabbix Blog.

## Requirements

This project requires the following Python packages, which are specified in the `requirements.txt` file:

```
zabbix_utils[async]>=2.0.0
flask[async]
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/aiantsen/zabbix-alert-tracker.git
```

2. Navigate to the project directory:

```bash
cd alert-tracker
```

3. Create a virtual environment (optional but recommended):

```bash
python -m venv venv
```

4. Activate the virtual environment:

- For Windows:

```
venv\Scripts\activate
```
- For macOS/Linux:

```bash
source venv/bin/activate
```
  
5. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

To run the application, use the following command:

```bash
flask run
```

You can then access the application at `http://127.0.0.1:5000`.

## Contributing

As this is a demonstration project, we welcome interest in further development. If you have suggestions, improvements, or fixes, please feel free to submit an issue.

**Disclaimer**: This is a prototype project. Its current state may not be suitable for production use. Please use it as a reference or foundation for your own implementations.

## License

This project is open source and available under the MIT License.
