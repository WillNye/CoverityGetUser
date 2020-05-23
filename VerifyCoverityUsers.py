"""
This Python app will contact the specified Coverity server with the Credentials provided
and download a list of userr.  It will then contact the specified LDAP server and verify the 
users still exist in LDAP.  Finally it will dump all valid user email addresses to a text 
file so that you can email them.

See the included configuration (cfg) file for settings needed for app to work properly.
"""
# Load the required imports
import sys
import ldap
import csv
import requests
import os.path
from os import path
import configparser

# Define Gobal Variables
ConfigFileName = "VerifyCoverityUsers.cfg"
ConfigDict = []
FoundUserCount = 0
MissingUserCount = 0
ListOfUsersToEmail = []

###################################################
# Functions definitions
###################################################

def connectToLDAPServer():
    """Method used to connect to the LDAP server."""
    #Bind to the server
    global ldapConnection
    print("Connecting to LDAP server [" + ldapServer + "] on port [" + ldapPort + "]...")

    # Initalize the LDAP Connection now
    ldapConnection = ldap.initialize('ldap://' + ldapServer + ':' + ldapPort)

    try:
        ldapConnection.protocol_version = ldap.VERSION3
        ldapConnection.simple_bind_s(ldapUser, ldapPassword) 
    except ldap.INVALID_CREDENTIALS:
        print ("FAILURE: LDAP username or password is incorrect.")
        sys.exit(1)
    except ldap.LDAPError as e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print (e.message['desc'])
        else: 
            print (e)
        sys.exit(1)


def disconnectFromLDAPServer():
    """Method used to disconnect from the LDAP server."""
    print("Disconnecting from LDAP server [" + ldapServer + "] on port [" + ldapPort + "]...")
    # Unbind from LDAP now that we are done.
    global ldapConnection
    ldapConnection.unbind_s()


def findUserInLDAP(emailAddress):
    """Method used to find a user in LDAP based on their mail attribute (Email Address)."""
    global ldapConnection
    print("   Searching LDAP for user with email address of :" + emailAddress)

    searchFilter = "(mail=" + emailAddress + ")"
    searchAttribute = ["mail"]

    try:
        ldap_result_id = ldapConnection.search(ldapBaseDN, ldap.SCOPE_SUBTREE, searchFilter, searchAttribute)
        result_set = []
        while 1:
            result_type, result_data = ldapConnection.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                ## if you are expecting multiple results you can append them
                ## otherwise you can just wait until the initial result and break out
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        if (result_set == []):
            # print ("User NOT Found")
            return False
        else:
            # print ("User found.")
            return True
    except ldap.LDAPError as e:
        print (e)
        sys.exit(1)


def SearchForUsers(UserToFind):
    """Method used to Search for the various users and act upon what it finds."""
    if (UserToFind != ""):
        if(findUserInLDAP(UserToFind) is True):
            print ("   User [" + UserToFind + "] was found.")
            global FoundUserCount
            FoundUserCount += 1
            global ListOfUsersToEmail
            ListOfUsersToEmail.append(UserToFind)
        else:
            print ("   User [" + UserToFind + "] was NOT found.")
            global MissingUserCount
            MissingUserCount += 1
    else:
        print("   Skipping blank user")


def ReadCoverityUsersFromWebsite():
    """Method used to connect to the Coverity server and read the list of users and write to a file."""
    siteToUse = coverityURL
    if (siteToUse.endswith("/")):
        siteToUse += "config/usergroup/users.csv?excludeDisabled=false"
    else:
        siteToUse += "/config/usergroup/users.csv?excludeDisabled=false"

    print ("   Reading Coverity user list from following webiste: " + siteToUse)
    result = requests.get(siteToUse, auth=(coverityUser, coverityPassword), verify=coverityPEMFile)
    with open(CoverityUsersFile, mode='w') as f:
        f.write(result.text)

    print ("   Reading Coverity user list from file...")
    with open(CoverityUsersFile, mode='r') as infile:
        reader = csv.reader(infile)
        {SearchForUsers(rows[3]) for rows in reader}


def WriteValidUsersToFile():
    """Method used to Write the valid users (still in LDAP) to a file."""
    print("Writing valid users to file: " + ValidCoverityUsers)
    with open(ValidCoverityUsers, mode='w') as f:
        for user in ListOfUsersToEmail:
            f.write("%s\n" % user)

def CreateBackupFiles():
    """Method used to create a backup of the two output files."""
    print ("Creating BAK files...")
    # Remove BAK files first
    if (path.exists(CoverityUsersFile + ".bak")):
        os.remove(CoverityUsersFile + ".bak")

    if (path.exists(ValidCoverityUsers + ".bak")):
        os.remove(ValidCoverityUsers + ".bak")

    # Create the BAK files
    if (path.exists(CoverityUsersFile)):
        os.rename(CoverityUsersFile, CoverityUsersFile + ".bak")

    if (path.exists(ValidCoverityUsers)):
        os.rename(ValidCoverityUsers, ValidCoverityUsers + ".bak")

def ReadStrFromConfigFile(configfile, section, option):
    """Method used to read a string value from a config file and return the string"""
    print("   * Reading section [" + section + "] and option [" + option + "] from config file [" + configfile + "] ...")
    config = configparser.RawConfigParser()
    config.read(configfile)
    if (config.has_option(section, option)):
        return config.get(section, option, raw=True)
    else:
        print("FAILURE: Either the section specified or the option specified was NOT found in config file so fail.")
        sys.exit(1)

def LoadConfigurationInfo():
    """Method used to load the configuration settings from the ConfigFileName file."""
    global ldapServer
    global ldapPort
    global ldapUser
    global ldapPassword
    global ldapBaseDN
    global coverityURL
    global coverityUser
    global coverityPassword
    global coverityPEMFile
    global CoverityUsersFile
    global ValidCoverityUsers
    if (path.exists(ConfigFileName)):
        print("Configuration file found so loading configuration...")

        ldapServer = ReadStrFromConfigFile(ConfigFileName, 'LDAP Settings', 'ldapServer')
        print ("      * LDAP Server set to : " + ldapServer)

        ldapPort = ReadStrFromConfigFile(ConfigFileName, 'LDAP Settings', 'ldapPort')
        print ("      * LDAP Port set to : " + ldapPort)

        ldapUser = ReadStrFromConfigFile(ConfigFileName, 'LDAP Settings', 'ldapUser')
        print ("      * LDAP User set to : " + ldapUser)

        ldapPassword = ReadStrFromConfigFile(ConfigFileName, 'LDAP Settings', 'ldapPassword')
        print ("      * LDAP Password set to : " + ldapPassword)

        ldapBaseDN = ReadStrFromConfigFile(ConfigFileName, 'LDAP Settings', 'ldapBaseDN')
        print ("      * LDAP BaseDN set to : " + ldapBaseDN)

        coverityURL = ReadStrFromConfigFile(ConfigFileName, 'Coverity Settings', 'coverityURL')
        print ("      * Coverity URL set to : " + coverityURL)

        coverityUser = ReadStrFromConfigFile(ConfigFileName, 'Coverity Settings', 'coverityUser')
        print ("      * Coverity Username set to : " + coverityUser)

        coverityPassword = ReadStrFromConfigFile(ConfigFileName, 'Coverity Settings', 'coverityPassword')
        print ("      * Coverity Password set to : " + coverityPassword)

        coverityPEMFile = ReadStrFromConfigFile(ConfigFileName, 'Coverity Settings', 'coverityPEMFile')
        print ("      * Coverity PEM File set to : " + coverityPEMFile)

        CoverityUsersFile = ReadStrFromConfigFile(ConfigFileName, 'Output Files', 'CoverityUsersFile')
        print ("      * Coverity Users Filename set to : " + CoverityUsersFile)

        ValidCoverityUsers = ReadStrFromConfigFile(ConfigFileName, 'Output Files', 'ValidCoverityUsers')
        print ("      * Valid Coverity Users Filename set to : " + ValidCoverityUsers)

        print ("Doen Loading Configuration Settings")

    else:
        print("FAILURE: Configuration file NOT found so failing")
        sys.exit(1)


###################################################
# Main calls go here
###################################################
print ('Number of arguments:', len(sys.argv), 'arguments.')
print ('Argument List:', str(sys.argv))

# Load up the configuration (MUST BE First)
LoadConfigurationInfo()

# Make sure both files are not present before we continue
CreateBackupFiles()

# Connect to LDAP server and verify the Coverity users with it
connectToLDAPServer()
ReadCoverityUsersFromWebsite()
disconnectFromLDAPServer()
WriteValidUsersToFile()

print ("Found user count   : " + str(FoundUserCount))
print ("Missing user count : " + str(MissingUserCount))
