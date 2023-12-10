# SNIScanner

### 1. Introduction

SNIScanner is a lightweight, automated measurement tool that can detect detailed server-side support for:

- Transport Layer Security (TLS);

- Encrypted SNI solutions on the web, including Encrypted Server Name Indication (ESNI), Encrypted Client Hello (ECH) and Quick UDP Internet Connections (QUIC).

Our code in this repository encompasses the core module for obtaining the main analysis data in our paper. To retrieve large-scale measurement data with our tool, please add your customized data parsing module(s) or make other necessary adjusments according to the specified domain data file format.

### 2. Installation

- Download SNIScanner to your device

    ```
    $ git clone https://github.com/ididChan/SNIScanner.git
    $ cd SNIScanner
    ```

- Install the requirements

    ```
    $ pip install -r requirements.txt
    ```

- Run SNIScanner

    ```
    $ python SNIScanner.py
    ```

### 3. How to use SNIScanner

While running SNIScanner, you can choose to scan a singe protocol (enter: `TLS`/`ESNI`/`ECH`/`QUIC`) or process all the scannings altogether (enter: `All`). The scanning results returned by our tool are listed as follows:

| Protocol |                                          Return Value                                          |
|:--------:|:----------------------------------------------------------------------------------------------:|
| TLS      | if_success, version_info (highest TLS/SSL version, ALPN version and NPN version) or error_info |
| ESNI     | if_success, ESNIKey_parsed or error_info                                                       |
| ECH      | if_success, ECHConfig_parsed or error_info                                                     |
| QUIC     | if_success, version_info or error_info                                                         |