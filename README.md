# CVE-searcher

CVE-searcher is a vulnerability parser that looks for CVE's from different sources. It employs the Shodan API, has the ability to retrieve and process data from [CVE Mitre](https://cve.mitre.org/) and comes with functionality to install and use Offensive Security's ExploitDB [Searchsploit](https://github.com/offensive-security/exploit-database/blob/master/searchsploit) utility. It's rewritten  [project](https://github.com/NullArray/PyParser-CVE)

## Usage

Start the program from the command line with `python cvesearcher.py`. Once the program has been started it will prompt for your Shodan.io API key. Once provided it will prompt to install Searchsploit, which is optional. After these operations a menu will be displayed the options for which are as follows.

```
1. Query Shodan				4. Quit
2. Query CVE Mitre			
3. Invoke Searchsploit				
```
Select a number to select a data source to use when searching for a particular vulnerability. The 'logging' option will save results of your search queries in the current working directory as an application log from CVE-searcher.

## Dependencies
CVE-searcher depends on the following Python 3.7 libraries.
```
blessings
shodan
pycurl
```
Should you find you do not have any of these libraries installed you can use Python's built in package manager to resolve it like so: 
```
pip install blessings
pip install shodan
pip install pycurl
```
Alternatively, feel free to use the requirements file i have made for this project like so `pip install -r requirements.txt`.

