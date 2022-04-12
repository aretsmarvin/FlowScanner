"""
Class for handling database queries.
"""
#! /usr/bin/env python

import os
import sys
import dotenv

import mysql.connector
from mysql.connector import errorcode

try:
    dotenv.load_dotenv('.env')

    connection = mysql.connector.connect(host=os.getenv('db_host'),
                                    username=os.getenv('db_username'),
                                    password=os.getenv('db_password'),
                                    database=os.getenv('db_database'),
                                    port=os.getenv('db_port', "3306"))
    cursor = connection.cursor()
except mysql.connector.Error as err:
    print(err)
    sys.exit()

def InsertOrUpdateIPPort(ip_address, port, proto) -> int:
    """
    Inserts a new IP port combo.
    Returns 1 on succes.
    Returns 0 when didn't add.
    """
    insert_ip_port = ("INSERT IGNORE INTO `scans`(`ipaddress`, `port`, `proto`)"
                    "VALUES (%s, %s, %s)"
                    "ON DUPLICATE KEY UPDATE last_scanned= NOW()")
    return Execute(insert_ip_port, False, (ip_address, port, proto,), True)

def GetLastScanTime(ip_address, port, proto) -> int:
    """
    Queries the scan time for an given IP port combo.
    Returns the time, or None when not found.
    """
    get_scan_time = ("SELECT `last_scanned` FROM `scans` WHERE"
                    "`ipaddress` = %s AND `port` = %s AND `proto` = %s")
    return Execute(get_scan_time, True, (ip_address, port, proto,), False)

def UpdateLastScanTime(ip_address, port, proto) -> int:
    """
    Updates the scan time for an given IP port combo.
    Returns 1 on success.
    Returns 0 when didn't change anything.
    """
    sql = ("UPDATE `scans` "
        "SET last_scanned = NOW()"
        "WHERE `ipaddress` = %s AND `port` = %s AND `proto` = %s")
    return Execute(sql, False, (ip_address, port, proto,), True)

def DeleteIPPortCombo(ip_address, port, proto) -> int:
    """
    Function to delete IP address and port entry from the database.
    Returns the amout of rows deleted.
    """
    delete_ip_port_combo = ("DELETE FROM `scans` WHERE `ipaddress` = %s"
                            "AND `port` = %s AND `proto` = %s")
    return Execute(delete_ip_port_combo, False, (ip_address, port, proto,), True)

def DatabaseSetup() -> int:
    """
    Function to create the database (setup)
    Returns -1 on failure.
    Returns 0 on succes.
    Returns 1 when database already exists.
    """
    insert_structure = ("CREATE TABLE `scans` ("
    "`id` int(11) NOT NULL,"
    "`ipaddress` varchar(64) NOT NULL,"
    "`port` mediumint(9) NOT NULL,"
    "`proto` ENUM('TCP', 'UDP'),"
    "`last_scanned` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp())"
    " ENGINE=InnoDB DEFAULT CHARSET=latin1;")
    try:
        Execute(insert_structure, False, (), True)
    except mysql.connector.Error as mysqlerror:
        if mysqlerror.errno == errorcode.ER_TABLE_EXISTS_ERROR:
            print("Table already exists")
            return 1
        return -1
    alter_unique = ("ALTER TABLE `scans`"
                    "ADD UNIQUE KEY `id` (`id`),"
                    "ADD UNIQUE KEY `unique_index` (`ipaddress`,`port`, `proto`);")
    try:
        Execute(alter_unique, False, (), True)
    except mysql.connector.Error:
        return -1

    alter_auto_increment = ("ALTER TABLE `scans`"
                        "MODIFY `id` int(11) NOT NULL AUTO_INCREMENT,"
                        "AUTO_INCREMENT=0;")
    try:
        Execute(alter_auto_increment, False, (), True)
    except mysql.connector.Error:
        return -1

    return 0

def Execute(sqltuple, single = False, args = None, commit = False) -> int:
    """
    Function that handles SQL queries.
    Returns amount of rows executed.
    """
    cursor.execute(sqltuple, args)

    if commit:
        connection.commit()
        return cursor.rowcount

    if single:
        return cursor.fetchone()

    return cursor.fetchall()


def Close():
    """
    Function to close database connection.
    """
    connection.close()
