"https://github.com/yaguar/cvesearcher/README.md"

import os.path
import pickle
import time
import sys
import csv
import shodan
import pycurl
from blessings import Terminal

T = Terminal()
print(T.bold+T.green("""

~####~~##~~##~#####~~~~~~~~~~####~~#####~~~####~~#####~~~####~~##~~##~#####~~#####
##~~##~##~~##~##~~~~~~~~~~~~##~~~~~##~~~~~##~~##~##~~##~##~~##~##~~##~##~~~~~##~~##
##~~~~~##~~##~####~~~#####~~~####~~####~~~######~#####~~##~~~~~######~####~~~#####
##~~##~~####~~##~~~~~~~~~~~~~~~~##~##~~~~~##~~##~##~~##~##~~##~##~~##~##~~~~~##~~##
~####~~~~##~~~#####~~~~~~~~~~####~~#####~~##~~##~##~~##~~####~~##~~##~#####~~##~~##

                                     Common Vulnerabilities and Exploits"""))

ERROR_MESSAGE = "[!]Critical. An error was raised with the following message."


def make_exploit_db():
    """
    Function to install and configure ExploitDB's Searchsploit utility
    """
    question = "Would you like CVE-seacher to install exploit-database?"
    print(T.italic("[" + T.green("?") + "]" + question))
    get_edb = input(T.green("[y]es/[n]o: "))

    if get_edb == 'y':
        print("[" + T.green("+") + "]Invoking git...")
        time.sleep(1)
        try:
            git = "https://github.com/offensive-security/exploit-database.git"
            os.system("git clone " + git)
            os.system("cd exploit-database && abspath=$(pwd) && "
                      "sudo ln -sf $abspath/searchsploit "
                      "/usr/local/bin/searchsploit && chmod +x searchsploit")
        except Exception as err:
            print(T.red(ERROR_MESSAGE))
            print(T.red(err))
            sys.exit(0)

        print("[" + T.green("+") + "]Completed")

    elif get_edb == 'n':
        print("[" + T.green("+") + "]Not installing.")
    else:
        print(T.red("[!]Unhandled option"))


def cve_mitre():
    """
     Function to install and configure cve_mitre.csv utility
    """
    if not os.path.isfile('cve_mitre.csv'):
        message_cve_mitre = "Fetching CVE Mitre data. This may take a while..."
        url_download = "http://cve.mitre.org/data/downloads/allitems.csv"
        print("[" + T.green("+") + "]" + message_cve_mitre)
        curl = pycurl.Curl()
        try:
            curl.setopt(curl.URL, url_download)
            with open('cve_mitre.csv', 'wb') as outfile:
                curl.setopt(curl.WRITEFUNCTION, outfile.write)
                curl.perform()
        except Exception as err:
            print(T.red(ERROR_MESSAGE))
            print(err)

        print("[" + T.green("+") + "]Complete")

    print("[" + T.green("+") + "]Please provide a search query.")
    query = input(T.green("<MITRE>$ "))

    with open('cve_mitre.csv', 'r', encoding='utf8', errors='ignore') as file:
        csv_reader = csv.reader(file)
        print(T.green("Do you want to write the result to a file?"))
        write_file = input(T.green("[y]es/[n]o: "))
        if write_file == 'y':
            with open('cve_mitre.log', 'w') as outfile:
                for row in csv_reader:
                    if query in str(row):
                        outfile.write(row)
                        outfile.write('\n')
                        outfile.write('\n')
        for row in csv_reader:
            if query in str(row):
                print(row, '\n\n')


def shodan_q():
    """
    Function to search in Shodan
    """
    print("[" + T.green("+") + "]Please provide a search query for shodan.")
    query = input(T.green("<SHODAN>$ "))
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.exploits.search(query, 5, 'author, platform, port, type')
        print(T.green("Do you want to write the result to a file?"))
        write_file = input(T.green("[y]es/[n]o: "))
        if write_file == 'y':
            with open('shodan_cve.log', 'w') as outfile:
                for result in results['matches']:
                    for key, value in result.items():
                        outfile.write(key + ': ' + str(value))
                        outfile.write('\n')
                    outfile.write('\n')
        else:
            for result in results['matches']:
                for key, value in result.items():
                    print(T.green(key+': '+str(value)))
                print('')

    except Exception as err:
        print(T.red(ERROR_MESSAGE))
        print(err)
    message_shodan_q = "Results have been saved to 'shodan_cve.log' " \
                       "in the current directory."
    print("[" + T.green("+") + "]" + message_shodan_q)


def s_sploit():
    """
    Function to search in  exploit-database
    """
    message_s_sploit = "Please provide a search query. Multiple terms " \
                       "are allowed in this module."
    print("[" + T.green("+") + "]" + message_s_sploit)
    query = input(T.green("<SEARCHSPLOIT>$ "))

    try:
        result = os.system("searchsploit -j " + query)
        print(T.green("Do you want to write the result to a file?"))
        write_file = input(T.green("[y]es/[n]o: "))
        if write_file == 'y':
            with open('searchsploit.log', 'w') as outfile:
                outfile.write(result)
        else:
            print(result)
    except Exception as err:
        print(T.red(ERROR_MESSAGE))
        print(err)


def return_action(action):
    """
    Function return one of the searchers

    :param action: str(int)
    """
    def check_exploit_database():
        if not os.path.isdir('exploit-database'):
            print(T.red("[!]Warning! Searchsploit was not installed."))
            msg_database = "Would you like CVE-searcher to automatically " \
                           "resolve this issue?"
            print(T.italic("[" + T.green("?") + "]" + msg_database))
            get_edb = input("[y]es/[n]o: ")
            if get_edb == 'y':
                return make_exploit_db()
            if get_edb == 'n':
                return print("[" + T.green("+") + "]Not resolving.")
            return print(T.red("[!]Unhandled option"))
        return s_sploit()
    actions = {
        '1': shodan_q,
        '2': cve_mitre,
        '3': check_exploit_database,
        '4': lambda: print(T.red("[!]Unhandled option"))
    }
    if action not in ['1', '2', '3']:
        action = '4'
    return actions.get(action)


def main():
    """Function to start"""
    try:
        while True:
            msg = "Welcome to CVE-searcher. Please select an action"
            print("[" + T.green("+") + "]" + msg)
            print('')
            print(T.green("1.") + " Query Shodan   " + T.green("4.") + " Quit")
            print(T.green("2.") + " Query CVE Mitre")
            print(T.green("3.") + " Invoke Searchsploit")
            action = input(T.green("<CVE-searcher>$ "))
            if action == '4':
                break
            return_action(action)()

    except KeyboardInterrupt:
        print(T.red("[!]Critical. User aborted."))


if __name__ == '__main__':
    if not os.path.isfile('api.p'):
        MESSAGE = "Welcome to CVE-searcher. Please provide your Shodan API Key"
        print("[" + T.green("+") + "]" + MESSAGE)
        SHODAN_API_KEY = input("API key: ")
        pickle.dump(SHODAN_API_KEY, open("api.p", "wb"))
        MESSAGE = "Your API key has been saved to 'Shodan_API.p' in the " \
                  "current directory."
        print("[" + T.green("+") + "]" + MESSAGE)
    else:
        SHODAN_API_KEY = pickle.load(open("api.p", "rb"))
        PATH = os.path.abspath("api.p")
        MESSAGE = "Your Shodan API key was successfully loaded from "
        print("[" + T.green("+") + "]" + MESSAGE + PATH)
    main()
