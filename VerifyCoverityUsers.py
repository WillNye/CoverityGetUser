"""This Python app will contact the specified Coverity server with the Credentials provided
and download a list of users and then contact the specified LDAP server and verify that the 
users still exist in LDAP.  Finally it will dump all valid users email addresses to a text 
file so that you can email them. """
# Load the required imports
import sys
import ldap
import csv
import requests
import os.path
from os import path

###################################################
# LDAP Settings
###################################################
ldapServer = "LDAP Server Name"
ldapPort = "LDAP Port Number"
ldapUser = "CN=Your LDAP Username"
ldapPassword = "Your LDAP Password"
ldapBaseDN = "OU=EMPLOYEES,OU=People,OU=Root,DC=corpzone,DC=internalzone,DC=com"
###################################################

###################################################
# Coverity Settings
###################################################
coverityURL = "Your Coverity server URL and Port"
coverityUser = "Coverity Admin Username"
coverityPassword = "Coverity Admin Password" # MUST be account password and NOT Authentication Key
###################################################

###################################################
# Files
###################################################
CoverityUsersFile = "CoverityUsers.txt"
ValidCoverityUsers = "ValidCoverityUsers.txt"
###################################################

# Define Gobal Variables
FoundUserCount = 0
MissingUserCount = 0
ListOfUsersToEmail = []

# Initalize the LDAP Connection now
ldapConnection = ldap.initialize('ldap://' + ldapServer + ':' + ldapPort)

###################################################
# Functions definitions
###################################################

def connectToLDAPServer():
    #Bind to the server
    global ldapConnection
    print("Connecting to LDAP server [" + ldapServer + "] on port [" + ldapPort + "]...")
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
    print("Disconnecting from LDAP server [" + ldapServer + "] on port [" + ldapPort + "]...")
    # Unbind from LDAP now that we are done.
    global ldapConnection
    ldapConnection.unbind_s()


def findUserInLDAP(emailAddress):
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
    print ("   Reading Coverity user list from webiste...")
    result = requests.get(coverityURL, auth=(coverityUser, coverityPassword))
    with open(CoverityUsersFile, mode='w') as f:
        f.write(result.text)

    print ("   Reading Coverity user list from file...")
    with open(CoverityUsersFile, mode='r') as infile:
        reader = csv.reader(infile)
        {SearchForUsers(rows[3]) for rows in reader}


def WriteValidUsersToFile():
    print("Writing valid users to file: " + ValidCoverityUsers)
    with open(ValidCoverityUsers, mode='w') as f:
        for user in ListOfUsersToEmail:
            f.write("%s\n" % user)

def CreateBackupFiles():
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



###################################################
# Main calls go here
###################################################
print ('Number of arguments:', len(sys.argv), 'arguments.')
print ('Argument List:', str(sys.argv))

# Make sure both files are not present before we continue
CreateBackupFiles()

connectToLDAPServer()
ReadCoverityUsersFromWebsite()
disconnectFromLDAPServer()
WriteValidUsersToFile()

print ("Found user count   : " + str(FoundUserCount))
print ("Missing user count : " + str(MissingUserCount))
